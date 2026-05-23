import { mkdtemp, rm, readFile, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import type { RiskFinding } from './types.js';

const execFile = promisify(execFileCb);

// ─── 1. OSV.dev malicious-package DB (npm or PyPI) ───────────
export async function checkOsv(
  pkg: string,
  version: string,
  ecosystem: 'npm' | 'PyPI' = 'npm'
): Promise<RiskFinding[]> {
  const findings: RiskFinding[] = [];
  const res = await fetch('https://api.osv.dev/v1/query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ package: { name: pkg, ecosystem }, version }),
  });
  const data = (await res.json()) as any;
  const vulns = data.vulns ?? [];
  const malVulns = vulns.filter((v: any) => v.id?.startsWith('MAL-'));
  const cveVulns = vulns.filter((v: any) => !v.id?.startsWith('MAL-'));

  for (const v of malVulns) {
    findings.push({
      level: 'critical',
      category: 'KNOWN MALICIOUS',
      message: `${v.id}: ${v.summary || v.details || 'See osv.dev'}`,
    });
  }
  for (const v of cveVulns.slice(0, 3)) {
    findings.push({
      level: 'medium',
      category: 'CVE',
      message: `${v.id}: ${v.summary || v.details || 'See osv.dev'}`,
    });
  }
  if (cveVulns.length > 3) {
    findings.push({
      level: 'low',
      category: 'CVE',
      message: `…and ${cveVulns.length - 3} more CVEs (see osv.dev)`,
    });
  }
  return findings;
}

// ─── 2a. npm registry metadata + install hooks ───────────────
export async function checkNpm(pkg: string, version: string) {
  const findings: RiskFinding[] = [];
  let tarballUrl: string | null = null;

  const res = await fetch(`https://registry.npmjs.org/${pkg}`);
  if (!res.ok) {
    findings.push({ level: 'high', category: 'METADATA', message: 'Package not found on npm' });
    return { findings, tarballUrl, actualVersion: version };
  }
  const data = (await res.json()) as any;
  const actualVersion = version === 'latest' ? data['dist-tags']?.latest : version;
  const target = data.versions?.[actualVersion];

  if (!target) {
    findings.push({ level: 'high', category: 'METADATA', message: `Version ${actualVersion} not found` });
    return { findings, tarballUrl, actualVersion };
  }

  tarballUrl = target.dist?.tarball ?? null;

  const ageDays = (Date.now() - new Date(data.time?.created).getTime()) / 86400000;
  if (ageDays < 30) {
    findings.push({ level: 'medium', category: 'REPUTATION', message: `Package only ${Math.round(ageDays)} days old` });
  }

  for (const hook of ['preinstall', 'postinstall', 'install'] as const) {
    if (target.scripts?.[hook]) {
      findings.push({
        level: hook === 'install' ? 'medium' : 'high',
        category: 'INSTALL HOOK',
        message: `${hook}: ${target.scripts[hook].slice(0, 120)}`,
      });
    }
  }

  if (data.deprecated || target.deprecated) {
    findings.push({ level: 'medium', category: 'DEPRECATED', message: String(data.deprecated || target.deprecated) });
  }

  return { findings, tarballUrl, actualVersion };
}

// ─── 2b. PyPI registry metadata + yanked detection ──────────
export async function checkPyPI(pkg: string, version: string) {
  const findings: RiskFinding[] = [];
  let downloadUrl: string | null = null;

  const res = await fetch(`https://pypi.org/pypi/${pkg}/json`);
  if (!res.ok) {
    findings.push({ level: 'high', category: 'METADATA', message: 'Package not found on PyPI' });
    return { findings, downloadUrl, actualVersion: version };
  }
  const data = (await res.json()) as any;
  const actualVersion = version === 'latest' ? data.info?.version : version;
  const releases = data.releases?.[actualVersion];

  if (!releases || releases.length === 0) {
    findings.push({ level: 'high', category: 'METADATA', message: `Version ${actualVersion} not found on PyPI` });
    return { findings, downloadUrl, actualVersion };
  }

  // Prefer sdist (.tar.gz) over wheel (.whl) for source inspection
  const sdist = releases.find((r: any) => r.packagetype === 'sdist');
  const wheel = releases.find((r: any) => r.packagetype === 'bdist_wheel');
  downloadUrl = sdist?.url ?? wheel?.url ?? releases[0]?.url ?? null;

  const uploadTime = sdist?.upload_time ?? releases[0]?.upload_time;
  if (uploadTime) {
    const ageDays = (Date.now() - new Date(uploadTime).getTime()) / 86400000;
    if (ageDays < 30) {
      findings.push({ level: 'medium', category: 'REPUTATION', message: `Package only ${Math.round(ageDays)} days old` });
    }
  }

  // Yanked = soft-removed from PyPI; strong signal
  const yanked = releases.find((r: any) => r.yanked);
  if (yanked) {
    findings.push({
      level: 'high',
      category: 'METADATA',
      message: `Yanked from PyPI${yanked.yanked_reason ? ': ' + yanked.yanked_reason : ''}`,
    });
  }

  // Missing author metadata is a low-confidence signal for typosquats
  if (!data.info?.author && !data.info?.author_email && !data.info?.maintainer) {
    findings.push({ level: 'low', category: 'REPUTATION', message: 'No author/maintainer metadata' });
  }

  return { findings, downloadUrl, actualVersion };
}

// ─── 3a. npm tarball download + static scan ──────────────────
export async function checkTarball(tarballUrl: string): Promise<{ findings: RiskFinding[]; mainCode: string }> {
  const findings: RiskFinding[] = [];
  let mainCode = '';
  const tmp = await mkdtemp(join(tmpdir(), 'safeinstall-'));
  try {
    const tarPath = join(tmp, 'pkg.tgz');
    const buf = Buffer.from(await (await fetch(tarballUrl)).arrayBuffer());
    await writeFile(tarPath, buf);
    await execFile('tar', ['-xzf', tarPath, '-C', tmp]);

    const pkgDir = join(tmp, 'package');
    const pkgJson = JSON.parse(await readFile(join(pkgDir, 'package.json'), 'utf8'));

    const candidates: string[] = [];
    if (pkgJson.main) candidates.push(pkgJson.main);
    if (pkgJson.module) candidates.push(pkgJson.module);
    if (typeof pkgJson.exports === 'string') candidates.push(pkgJson.exports);
    if (pkgJson.exports?.['.']) {
      const dot = pkgJson.exports['.'];
      if (typeof dot === 'string') candidates.push(dot);
      else if (typeof dot === 'object') {
        for (const key of ['import', 'require', 'default', 'node']) {
          const v = dot[key];
          if (typeof v === 'string') candidates.push(v);
          else if (v?.default && typeof v.default === 'string') candidates.push(v.default);
        }
      }
    }
    candidates.push('index.js', 'index.mjs', 'index.cjs', 'src/index.js', 'lib/index.js', 'dist/index.js', 'source/index.js');

    for (const c of candidates) {
      if (!c) continue;
      try {
        const content = await readFile(join(pkgDir, c), 'utf8');
        if (content.length > 50) { mainCode = content; break; }
      } catch {}
    }

    const found = await execFile('find', [pkgDir, '-name', '*.js', '-type', 'f', '-maxdepth', '3']);
    const files = found.stdout.split('\n').filter(Boolean).slice(0, 20);
    let evalBase64 = 0, netExec = 0, obfusc = 0;

    for (const f of files) {
      const c = await readFile(f, 'utf8');
      if (/eval\s*\(\s*(?:atob|Buffer\.from[^)]+base64)/.test(c)) evalBase64++;
      if (/(child_process|spawn|exec)\b[\s\S]{0,200}https?:\/\//.test(c)) netExec++;
      if (/(_0x[a-f0-9]{4,}|\\x[0-9a-f]{2}){10,}/i.test(c)) obfusc++;
    }

    if (evalBase64) findings.push({ level: 'critical', category: 'STATIC', message: `${evalBase64} eval+base64 patterns (classic obfuscation)` });
    if (netExec)    findings.push({ level: 'high',     category: 'STATIC', message: `${netExec} files combining network calls with process exec` });
    if (obfusc)     findings.push({ level: 'high',     category: 'STATIC', message: `${obfusc} files with heavy hex/unicode obfuscation` });
  } catch (err) {
    findings.push({ level: 'info', category: 'STATIC', message: `Tarball scan skipped: ${err}` });
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
  return { findings, mainCode };
}

// ─── 3b. PyPI sdist download + setup.py scan + static scan ───
export async function checkPyPISdist(downloadUrl: string): Promise<{ findings: RiskFinding[]; mainCode: string }> {
  const findings: RiskFinding[] = [];
  let mainCode = '';
  const tmp = await mkdtemp(join(tmpdir(), 'safeinstall-py-'));

  try {
    const archivePath = join(tmp, downloadUrl.endsWith('.whl') ? 'pkg.whl' : 'pkg.tar.gz');
    const buf = Buffer.from(await (await fetch(downloadUrl)).arrayBuffer());
    await writeFile(archivePath, buf);

    const extractDir = join(tmp, 'extracted');
    await mkdir(extractDir, { recursive: true });

    if (downloadUrl.endsWith('.whl') || downloadUrl.endsWith('.zip')) {
      await execFile('unzip', ['-q', archivePath, '-d', extractDir]);
    } else {
      await execFile('tar', ['-xzf', archivePath, '-C', extractDir]);
    }

    // Find top-level dir (sdist usually has one like pkgname-1.0.0/)
    const lsResult = await execFile('ls', [extractDir]);
    const entries = lsResult.stdout.trim().split('\n').filter(Boolean);
    if (entries.length === 0) {
      findings.push({ level: 'info', category: 'STATIC', message: 'Empty archive' });
      return { findings, mainCode };
    }
    const pkgDir = join(extractDir, entries[0]);

    // ─── setup.py — Python's install-hook equivalent ───────
    try {
      const setupPy = await readFile(join(pkgDir, 'setup.py'), 'utf8');
      const hasDangerousImports = /\b(subprocess|os\.system|os\.popen|urllib|requests|socket|pty|ctypes|paramiko)\b/.test(setupPy);
      const hasExecPatterns = /\b(exec|eval|compile|__import__)\s*\(/.test(setupPy);
      const hasBase64 = /\b(base64|b64decode|b64encode|fromhex)\b/.test(setupPy);

      if ((hasDangerousImports || hasExecPatterns) && hasBase64) {
        findings.push({
          level: 'critical',
          category: 'INSTALL HOOK',
          message: 'setup.py contains base64 decoding + exec/network patterns (classic install-time payload)',
        });
      } else if (hasExecPatterns || hasDangerousImports) {
        findings.push({
          level: 'high',
          category: 'INSTALL HOOK',
          message: 'setup.py contains exec/subprocess/network code that runs during pip install',
        });
      }
    } catch {
      // No setup.py — modern packages may use pyproject.toml only, which is declarative and safer
    }

    // ─── Find main package code ─────────────────────────────
    const pkgName = entries[0].split('-')[0].replace(/_/g, '-');
    const altName = entries[0].split('-')[0]; // some packages use underscores in dir
    const candidates = [
      `${altName}/__init__.py`,
      `${pkgName}/__init__.py`,
      `src/${altName}/__init__.py`,
      `src/${pkgName}/__init__.py`,
      `${altName}.py`,
      'setup.py',
    ];

    for (const c of candidates) {
      try {
        const content = await readFile(join(pkgDir, c), 'utf8');
        if (content.length > 50) { mainCode = content; break; }
      } catch {}
    }

    // ─── Pattern scan on .py files ───────────────────────────
    const found = await execFile('find', [pkgDir, '-name', '*.py', '-type', 'f', '-maxdepth', '4']);
    const files = found.stdout.split('\n').filter(Boolean).slice(0, 30);
    let execBase64 = 0, netExec = 0, obfusc = 0;

    for (const f of files) {
      const c = await readFile(f, 'utf8');
      if (/(?:exec|eval)\s*\(\s*[^)]{0,200}(?:base64|b64decode|fromhex)/.test(c)) execBase64++;
      if (/(subprocess|os\.system|os\.popen|pty\.spawn)\b[\s\S]{0,300}(urllib|requests|socket|http)/.test(c)) netExec++;
      if (/(\\x[0-9a-f]{2}){15,}/i.test(c) || /(?:chr\(\d+\)\s*\+\s*){5,}/.test(c)) obfusc++;
    }

    if (execBase64) findings.push({ level: 'critical', category: 'STATIC', message: `${execBase64} exec+base64 patterns (Python payload obfuscation)` });
    if (netExec)    findings.push({ level: 'high',     category: 'STATIC', message: `${netExec} files combining network with subprocess execution` });
    if (obfusc)     findings.push({ level: 'high',     category: 'STATIC', message: `${obfusc} files with character/hex obfuscation` });
  } catch (err) {
    findings.push({ level: 'info', category: 'STATIC', message: `Sdist scan skipped: ${err}` });
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
  return { findings, mainCode };
}

// ─── 4. LLM-powered code review (language-aware) ─────────────
export async function checkLlm(pkg: string, code: string, language: 'javascript' | 'python' = 'javascript'): Promise<RiskFinding[]> {
  const findings: RiskFinding[] = [];

  if (!process.env.OPENROUTER_API_KEY) {
    findings.push({ level: 'info', category: 'LLM', message: 'OPENROUTER_API_KEY not set' });
    return findings;
  }
  if (!code || code.length < 50) {
    findings.push({ level: 'info', category: 'LLM', message: `No main code to analyze (got ${code.length} chars)` });
    return findings;
  }

  const ecosystemName = language === 'python' ? 'PyPI' : 'npm';
  const prompt = `Analyze this ${ecosystemName} package for security risks. Look for: credential exfiltration, suspicious network calls, obfuscation, backdoors, persistence, install-time payloads.

Package: ${pkg}
Code (first 6000 chars):
\`\`\`${language}
${code.slice(0, 6000)}
\`\`\`

Respond with ONLY valid JSON (no preamble, no markdown):
{"risk_score": 0-10, "summary": "what this code does in 1 sentence", "concerns": ["concern1", "concern2"]}

Important: only list concerns about THIS package's code. Do NOT mention analysis limitations, code truncation, or generic advice like "use latest version". If no real concerns, return concerns: [].`;

  try {
    const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: process.env.SAFEINSTALL_MODEL || 'openai/gpt-4.1-mini',
        messages: [{ role: 'user', content: prompt }],
        max_tokens: 500,
      }),
    });
    const data = (await res.json()) as any;

    if (!res.ok) {
      findings.push({ level: 'info', category: 'LLM', message: `API ${res.status}: ${JSON.stringify(data).slice(0, 200)}` });
      return findings;
    }

    const content = data.choices?.[0]?.message?.content ?? '';
    if (!content) {
      findings.push({ level: 'info', category: 'LLM', message: 'Empty response from model' });
      return findings;
    }

    const match = content.match(/\{[\s\S]*\}/);
    if (!match) {
      findings.push({ level: 'info', category: 'LLM', message: `No JSON in response: ${content.slice(0, 200)}` });
      return findings;
    }

    try {
      const p = JSON.parse(match[0]);
      const s = Number(p.risk_score) || 0;
      findings.push({
        level: s >= 7 ? 'critical' : s >= 4 ? 'high' : s >= 2 ? 'medium' : 'low',
        category: 'LLM REVIEW',
        message: `${p.summary || 'no summary'} [score ${s}/10]`,
      });
      for (const c of p.concerns ?? []) {
        if (/partial|truncat|complete (audit|source|code)|require.*review/i.test(c)) continue;
        if (/use.*latest|update.*version|patched.*version|upgrade/i.test(c)) continue;
        findings.push({ level: 'medium', category: 'LLM CONCERN', message: c });
      }
    } catch (e) {
      findings.push({ level: 'info', category: 'LLM', message: `JSON parse failed on: ${match[0].slice(0, 200)}` });
    }
  } catch (err) {
    findings.push({ level: 'info', category: 'LLM', message: `Request failed: ${err}` });
  }

  return findings;
}

// ─── Aggregator with auto-escalate for MAL + removed ─────────
export function score(findings: RiskFinding[]) {
  const weights = { critical: 50, high: 25, medium: 10, low: 3, info: 0 } as const;
  const total = Math.min(100, findings.reduce((s, f) => s + weights[f.level], 0));

  const hasMal = findings.some((f) => f.category === 'KNOWN MALICIOUS');
  const removedFromRegistry = findings.some(
    (f) => f.category === 'METADATA' && (f.message.includes('not found') || f.message.includes('Yanked')),
  );
  if (hasMal && removedFromRegistry) {
    return { total: 100, verdict: 'block' as const };
  }

  const verdict = total >= 70 ? 'block' : total >= 30 ? 'warn' : 'allow';
  return { total, verdict };
}
