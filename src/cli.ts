#!/usr/bin/env node
import { checkOsv, checkNpm, checkTarball, checkLlm, score } from './scan.js';

const ICONS = { critical: '🚨', high: '⚠️ ', medium: '⚡', low: '·', info: 'ℹ️ ' };

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 2 || args[0] !== 'npm') {
    console.error('Usage: safeinstall npm <package>[@version]\n  e.g. safeinstall npm chalk@5.3.0');
    process.exit(1);
  }
  const [pkg, v = 'latest'] = args[1].split('@');
  const t0 = Date.now();
  console.log(`Scanning ${pkg}@${v}…\n`);

  const npmCheck = await checkNpm(pkg, v);
  const actualVersion = npmCheck.actualVersion;
  const [osv, tarball] = await Promise.all([
    checkOsv(pkg, actualVersion),
    npmCheck.tarballUrl ? checkTarball(npmCheck.tarballUrl) : Promise.resolve({ findings: [], mainCode: '' }),
  ]);
  const llm = await checkLlm(pkg, tarball.mainCode);

  const all = [...osv, ...npmCheck.findings, ...tarball.findings, ...llm];
  const { total, verdict } = score(all);
  const ms = Date.now() - t0;

  const bar = '─'.repeat(60);
  console.log(bar);
  console.log(`${pkg}@${actualVersion}`);
  console.log(`Risk: ${total}/100   Verdict: ${verdict === 'block' ? '🚫 BLOCK' : verdict === 'warn' ? '⚠️  WARN' : '✅ ALLOW'}   (${ms}ms)`);
  console.log(bar);
  if (!all.length) console.log('No findings.');
  for (const f of all) console.log(`${ICONS[f.level]} [${f.category}] ${f.message}`);

  process.exit(verdict === 'block' ? 2 : verdict === 'warn' ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(99); });
