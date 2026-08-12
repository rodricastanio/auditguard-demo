// ============================================================================
// run-on-actions.mjs — Ejecuta los engines REALES de AuditGuard en GitHub
// Actions y escribe report.md.
//
// Importa los mismos módulos que ejecuta la Action (dist/rules/*-engine.js y
// dist/report/markdown-generator.js) y los invoca con la misma firma que
// src/index.ts. El GITHUB_STEP_SUMMARY no se puede redirigir a un archivo
// (el runner lo inyecta por paso), así que este script materializa el reporte.
//
// Uso (workflow): node scripts/run-on-actions.mjs
//   Requiere AuditGuard clonado en ./AuditGuard con `npm ci --production` y
//   semgrep CLI instalado (igual que action.yml).
// ============================================================================

import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const repoRoot = process.env.GITHUB_WORKSPACE || process.cwd();
const auditGuardPath = path.join(repoRoot, 'AuditGuard');
const scanPath = process.env.AUDITGUARD_SCAN_PATH || './sample';

const { runEslintEngine } = await import(pathToFileURL(path.join(auditGuardPath, 'dist/rules/eslint-engine.js')));
const { runSemgrepEngine } = await import(pathToFileURL(path.join(auditGuardPath, 'dist/rules/semgrep-engine.js')));
const { runNpmAuditEngine } = await import(pathToFileURL(path.join(auditGuardPath, 'dist/rules/npm-audit-engine.js')));
const { deduplicateFindings } = await import(pathToFileURL(path.join(auditGuardPath, 'dist/rules/deduplicator.js')));
const { generateMarkdownReport } = await import(pathToFileURL(path.join(auditGuardPath, 'dist/report/markdown-generator.js')));

const allFindings = [];
const engineFailures = [];

console.log('[auditguard] ESLint scan...');
try {
  const findings = await runEslintEngine(scanPath);
  console.log(`[auditguard] ESLint: ${findings.length} findings`);
  allFindings.push(...findings);
} catch (error) {
  console.warn(`[auditguard] ESLint failed: ${error.message}`);
  engineFailures.push({ engine: 'eslint', error: error.message });
}

console.log('[auditguard] Semgrep scan...');
try {
  const findings = await runSemgrepEngine(scanPath, ['p/default', 'p/security-audit', 'p/owasp-top-ten']);
  console.log(`[auditguard] Semgrep: ${findings.length} findings`);
  allFindings.push(...findings);
} catch (error) {
  console.warn(`[auditguard] Semgrep failed: ${error.message}`);
  engineFailures.push({ engine: 'semgrep', error: error.message });
}

console.log('[auditguard] npm audit...');
try {
  const findings = await runNpmAuditEngine(scanPath, 'en');
  console.log(`[auditguard] npm audit: ${findings.length} findings`);
  allFindings.push(...findings);
} catch (error) {
  console.warn(`[auditguard] npm audit failed: ${error.message}`);
  engineFailures.push({ engine: 'npm-audit', error: error.message });
}

const deduplicated = deduplicateFindings(allFindings);
console.log(`[auditguard] After deduplication: ${deduplicated.length} findings`);

const meta = {
  repo: process.env.GITHUB_REPOSITORY,
  branch: process.env.GITHUB_REF_NAME,
  commit: process.env.GITHUB_SHA ? process.env.GITHUB_SHA.slice(0, 7) : undefined,
  scanPath,
};

const report = generateMarkdownReport(deduplicated, meta, engineFailures, 'en');
writeFileSync(path.join(repoRoot, 'report.md'), report, 'utf8');
console.log(`[auditguard] Report written (${report.length} chars)`);
