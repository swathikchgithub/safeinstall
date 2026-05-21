import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import type { RiskFinding } from './types.js';

const execFile = promisify(execFileCb);

// ─── 1. OSV.dev malicious-package DB ─────────────────────────
export async function checkOsv(pkg: string, version: string): Promise<RiskFinding[]> {
  const findings: RiskFinding[] = [];
  const res = await fetch('https://api.osv.dev/v1/query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ package: { name: pkg, ecosystem: 'npm' }, version }),
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

// ─── 2. npm registry metadata + install hooks ────────────────
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

// ─── 3. Tarball download + static pattern scan ───────────────
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

    // Build list of entry-point candidates to handle ESM packages
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
        if (content.length > 50) {
          mainCode = content;
          break;
        }
      } catch {}
    }

    // Pattern scan on top-level JS files
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

// ─── 4. LLM-powered code review (always emits a finding) ─────
export async function checkLlm(pkg: string, code: string): Promise<RiskFinding[]> {
  const findings: RiskFinding[] = [];

  if (!process.env.OPENROUTER_API_KEY) {
    findings.push({ level: 'info', category: 'LLM', message: 'OPENROUTER_API_KEY not set' });
    return findings;
  }
  if (!code || code.length < 50) {
    findings.push({ level: 'info', category: 'LLM', message: `No main code to analyze (got ${code.length} chars)` });
    return findings;
  }

  const prompt = `Analyze this npm package for security risks. Look for: credential exfiltration, suspicious network calls, obfuscation, backdoors, persistence, postinstall payloads.

Package: ${pkg}
Code (first 6000 chars):
\`\`\`javascript
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
        model: process.env.SAFEINSTALL_MODEL || 'minimax/minimax-m2.7',
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
        // Filter meta-concerns about the analysis/tool, not the package
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
    (f) => f.category === 'METADATA' && (f.message.includes('not found') || f.message.includes('Version')),
  );
  if (hasMal && removedFromRegistry) {
    return { total: 100, verdict: 'block' as const };
  }

  const verdict = total >= 70 ? 'block' : total >= 30 ? 'warn' : 'allow';
  return { total, verdict };
}
