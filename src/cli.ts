#!/usr/bin/env node
import { checkOsv, checkNpm, checkPyPI, checkTarball, checkPyPISdist, checkLlm, score } from './scan.js';
import type { RiskFinding } from './types.js';

const ICONS = { critical: '🚨', high: '⚠️ ', medium: '⚡', low: '·', info: 'ℹ️ ' };

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 2 || !['npm', 'pip'].includes(args[0])) {
    console.error('Usage: safeinstall <npm|pip> <package>[@version]');
    console.error('  e.g. safeinstall npm chalk@5.3.0');
    console.error('  e.g. safeinstall pip requests==2.31.0');
    console.error('  e.g. safeinstall pip requests');
    process.exit(1);
  }

  const ecosystem = args[0] as 'npm' | 'pip';
  // npm uses @ for version, pip conventionally uses ==
  const sep = ecosystem === 'pip' && args[1].includes('==') ? '==' : '@';
  const [pkg, v = 'latest'] = args[1].split(sep);

  const t0 = Date.now();
  console.log(`Scanning ${pkg}${v !== 'latest' ? sep + v : ''} on ${ecosystem}…\n`);

  let all: RiskFinding[] = [];
  let actualVersion = v;

  if (ecosystem === 'npm') {
    const npmCheck = await checkNpm(pkg, v);
    actualVersion = npmCheck.actualVersion;
    const [osv, tarball] = await Promise.all([
      checkOsv(pkg, actualVersion, 'npm'),
      npmCheck.tarballUrl ? checkTarball(npmCheck.tarballUrl) : Promise.resolve({ findings: [], mainCode: '' }),
    ]);
    const llm = await checkLlm(pkg, tarball.mainCode, 'javascript');
    all = [...osv, ...npmCheck.findings, ...tarball.findings, ...llm];
  } else {
    const pyCheck = await checkPyPI(pkg, v);
    actualVersion = pyCheck.actualVersion;
    const [osv, sdist] = await Promise.all([
      checkOsv(pkg, actualVersion, 'PyPI'),
      pyCheck.downloadUrl ? checkPyPISdist(pyCheck.downloadUrl) : Promise.resolve({ findings: [], mainCode: '' }),
    ]);
    const llm = await checkLlm(pkg, sdist.mainCode, 'python');
    all = [...osv, ...pyCheck.findings, ...sdist.findings, ...llm];
  }

  const { total, verdict } = score(all);
  const ms = Date.now() - t0;
  const ecoTag = ecosystem === 'pip' ? 'PyPI' : 'npm';

  const bar = '─'.repeat(60);
  console.log(bar);
  console.log(`${pkg}@${actualVersion} (${ecoTag})`);
  console.log(`Risk: ${total}/100   Verdict: ${verdict === 'block' ? '🚫 BLOCK' : verdict === 'warn' ? '⚠️  WARN' : '✅ ALLOW'}   (${ms}ms)`);
  console.log(bar);
  if (!all.length) console.log('No findings.');
  for (const f of all) console.log(`${ICONS[f.level]} [${f.category}] ${f.message}`);

  process.exit(verdict === 'block' ? 2 : verdict === 'warn' ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(99); });
