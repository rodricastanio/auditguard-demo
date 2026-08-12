// ============================================================================
// run-local.mjs — genera report.md ejecutando los engines reales de AuditGuard
// de forma local (sin GitHub Actions).
//
// Uso: node scripts/run-local.mjs [scan-path] [auditguard-path]
//   scan-path      default: ./sample
//   auditguard-path default: ../auditGuard  (repo clonado, con `npm install` y `npm run build`)
//
// Requiere semgrep CLI en el PATH para el engine de Semgrep. Si no está
// disponible, el engine fallará y se documentará en la sección de errores
// del reporte (comportamiento real de AuditGuard).
// ============================================================================

import { execSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');

const scanPath = path.resolve(repoRoot, process.argv[2] || './sample');
const auditGuardPath = path.resolve(repoRoot, process.argv[3] || '../auditGuard');

const { runEslintEngine } = await import(pathToFileURL(path.join(auditGuardPath, 'dist/rules/eslint-engine.js')));
const { runSemgrepEngine } = await import(pathToFileURL(path.join(auditGuardPath, 'dist/rules/semgrep-engine.js')));
const { runNpmAuditEngine } = await import(pathToFileURL(path.join(auditGuardPath, 'dist/rules/npm-audit-engine.js')));
const { deduplicateFindings } = await import(pathToFileURL(path.join(auditGuardPath, 'dist/rules/deduplicator.js')));
const { generateMarkdownReport } = await import(pathToFileURL(path.join(auditGuardPath, 'dist/report/markdown-generator.js')));

function git(args) {
  try {
    return execSync(`git ${args}`, { cwd: repoRoot, encoding: 'utf8' }).trim();
  } catch {
    return undefined;
  }
}

const allFindings = [];
const engineFailures = [];

console.log('[run-local] ESLint scan...');
try {
  const findings = await runEslintEngine(scanPath);
  console.log(`[run-local] ESLint: ${findings.length} findings`);
  allFindings.push(...findings);
} catch (error) {
  console.warn(`[run-local] ESLint failed: ${error.message}`);
  engineFailures.push({ engine: 'eslint', error: error.message });
}

console.log('[run-local] Semgrep scan...');
try {
  const findings = await runSemgrepEngine(scanPath, ['p/default', 'p/security-audit', 'p/owasp-top-ten']);
  console.log(`[run-local] Semgrep: ${findings.length} findings`);
  allFindings.push(...findings);
} catch (error) {
  console.warn(`[run-local] Semgrep failed: ${error.message}`);
  engineFailures.push({ engine: 'semgrep', error: error.message });
}

console.log('[run-local] npm audit...');
try {
  const findings = await runNpmAuditEngine(scanPath, 'en');
  console.log(`[run-local] npm audit: ${findings.length} findings`);
  allFindings.push(...findings);
} catch (error) {
  console.warn(`[run-local] npm audit failed: ${error.message}`);
  engineFailures.push({ engine: 'npm-audit', error: error.message });
}

const deduplicated = deduplicateFindings(allFindings);
console.log(`[run-local] After deduplication: ${deduplicated.length} findings`);

const meta = {
  repo: git('config --get remote.origin.url') || undefined,
  branch: git('branch --show-current') || undefined,
  commit: git('rev-parse --short HEAD') || undefined,
  scanPath,
};

const report = generateMarkdownReport(deduplicated, meta, engineFailures, 'en');
const outPath = path.join(repoRoot, 'report.md');
await import('node:fs/promises').then((fs) => fs.writeFile(outPath, report, 'utf8'));
console.log(`[run-local] Report written to ${outPath} (${report.length} chars)`);
