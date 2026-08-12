// ============================================================================
// renderer.js — Renderiza report.md (generado por AuditGuard) en la página.
// Parser ad-hoc del formato markdown emitido por AuditGuard (report/markdown-generator.ts).
// ============================================================================

const REPORT_PATH = './report.md';

const SEVERITY_LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' };
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const ENGINE_META = {
  eslint: { label: 'ESLint', desc: 'análisis estático (16 reglas de seguridad)' },
  semgrep: { label: 'Semgrep', desc: 'detección por patrones (12 reglas)' },
  'npm-audit': { label: 'npm audit', desc: 'CVEs conocidos en dependencias' },
};

const $ = (sel) => document.querySelector(sel);

// ---------- utilidades ----------

function unescapeMarkdown(s) {
  return s
    .replace(/\\_/g, '_')
    .replace(/\\\*/g, '*')
    .replace(/\\`/g, '`')
    .replace(/\\\[/g, '[')
    .replace(/\\\]/g, ']')
    .replace(/\\#/g, '#')
    .replace(/\\\\/g, '\\');
}

function severityFromText(text) {
  const t = (text || '').toUpperCase();
  if (t.includes('CRITICAL')) return 'critical';
  if (t.includes('HIGH')) return 'high';
  if (t.includes('MEDIUM')) return 'medium';
  if (t.includes('LOW')) return 'low';
  return 'info';
}

// Normaliza rutas absolutas (Windows o runner de GH Actions) y relativas
// de semgrep a una ruta relativa al repo, ej: "sample/src/app.js".
function normalizeFile(raw) {
  let p = String(raw || '').trim().replace(/^`|`$/g, '');
  p = p.replace(/\\/g, '/');
  const marker = '/sample/';
  const idx = p.lastIndexOf(marker);
  if (idx !== -1) return p.slice(idx + 1);
  if (p.startsWith('sample/')) return p;
  if (p === 'package.json') return 'sample/package.json';
  return 'sample/' + p;
}

function parseCwe(cell) {
  const m = String(cell || '').match(/\[(CWE-\d+)[^\]]*\]\(([^)]+)\)/);
  if (m) return { cwe: m[1], url: m[2] };
  const plain = String(cell || '').trim().match(/^(CWE-\d+)$/);
  return plain ? { cwe: plain[1], url: null } : null;
}

function splitFileLine(cell) {
  let raw = String(cell || '').trim().replace(/^`|`$/g, '');
  const m = raw.match(/^(.*):(\d+)$/);
  if (m) return { path: m[1], line: parseInt(m[2], 10) };
  return { path: raw, line: null };
}

// ---------- parser ----------

function parseReport(md) {
  md = String(md || '').replace(/\r\n?/g, '\n');
  const lines = md.split('\n');
  const report = {
    warnings: [],
    meta: {},
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    findings: [],
    npmAudit: [],
    engines: [],
  };

  let state = 'idle'; // idle | summary | finding | npm | files
  let current = null;
  let currentGroup = null; // lista de findings del grupo actual (re-ordenado luego)
  let block = null; // bloque blockquote en curso

  const flushBlock = () => {
    if (block) { report.warnings.push(block); block = null; }
  };

  const startFinding = (header) => {
    flushBlock();
    const sep = header.indexOf(' — ');
    current = {
      id: (sep !== -1 ? header.slice(0, sep) : header).trim(),
      message: unescapeMarkdown(sep !== -1 ? header.slice(sep + 3).trim() : ''),
      severity: null,
      file: null,
      line: null,
      rule: null,
      cwe: null,
      cweUrl: null,
      engine: null,
      explanation: '',
      suggestion: '',
      raw: [],
    };
    report.findings.push(current);
    state = 'finding';
  };

  const finishFinding = () => {
    if (current && current.severity) {
      // derivar file/line de la celda File
      if (current.file) {
        const fl = splitFileLine(current.file);
        current.file = fl.path;
        current.line = fl.line;
      }
      current = null;
    }
    state = 'idle';
  };

  for (const rawLine of lines) {
    const line = rawLine;

    // Bloque blockquote (warnings/cautions)
    if (line.startsWith('> ')) {
      const content = line.slice(2);
      const kind = content.match(/^\[!(WARNING|CAUTION|NOTE)\]/);
      if (!block) block = { type: kind ? kind[1].toLowerCase() : 'note', lines: [] };
      if (kind) block.type = kind[1].toLowerCase();
      else block.lines.push(content);
      continue;
    } else {
      flushBlock();
    }

    // Meta
    const metaMatch = line.match(/^\*\*(Repo|Branch|Commit|Scan path|Date):\*\*\s*(.*)$/);
    if (metaMatch) {
      const key = { Repo: 'repo', Branch: 'branch', Commit: 'commit', 'Scan path': 'scanPath', Date: 'date' }[metaMatch[1]];
      report.meta[key] = unescapeMarkdown(metaMatch[2].trim().replace(/^`|`$/g, ''));
      continue;
    }

    // Secciones y headers
    const h2 = line.match(/^##\s+(.*)$/);
    const h3 = line.match(/^###\s+(.*)$/);
    const detailsOpen = line.match(/^<details>$/);
    const detailsClose = line.match(/^<\/details>$/);
    const summaryTag = line.match(/^<summary>(.*)<\/summary>$/);
    const sepLine = /^---+$/.test(line.trim());

    if (h2) {
      finishFinding();
      state = h2[1].toLowerCase();
      continue;
    }

    if (detailsClose) {
      finishFinding();
      state = 'idle';
      continue;
    }

    if (h3) {
      finishFinding();
      startFinding(h3[1]);
      continue;
    }

    if (state === 'finding' && sepLine) {
      finishFinding();
      continue;
    }

    // --- parsing dentro de estados ---

    if (state === 'finding' && current) {
      current.raw.push(line);

      const tableRow = line.match(/^\|\s*\*\*([^*]+)\*\*\s*\|\s*(.*?)\s*\|$/);
      if (tableRow) {
        const [, field, value] = tableRow;
        switch (field.trim()) {
          case 'Severity': current.severity = severityFromText(value); break;
          case 'File': current.file = value; break;
          case 'Rule': current.rule = unescapeMarkdown(value).replace(/^`|`$/g, ''); break;
          case 'CWE': { const c = parseCwe(value); if (c) { current.cwe = c.cwe; current.cweUrl = c.url; } break; }
          case 'Engine': current.engine = value.trim(); break;
        }
      } else if (line.startsWith('**Explanation:**')) {
        current.explanation = unescapeMarkdown(line.slice('**Explanation:**'.length).trim());
      } else if (line.startsWith('**Suggestion:**')) {
        current.suggestion = unescapeMarkdown(line.slice('**Suggestion:**'.length).trim());
      }
      continue;
    }

    if (state === 'summary' && line.startsWith('|')) {
      const m = line.match(/^\|\s*\*\*?Total\*\*?\s*\|\s*\*\*?(\d+)\*\*?\s*\|/);
      if (m) { report.summary.total = parseInt(m[1], 10); continue; }
      const row = line.match(/^\|\s*(🔴|🟠|🟡|🔵|⚪)\s*([A-Z]+)\s*\|\s*(\d+)\s*\|/);
      if (row) {
        const sev = severityFromText(row[2]);
        report.summary[sev] = parseInt(row[3], 10);
      }
      continue;
    }

    if (state === 'npm audit' && line.startsWith('|')) {
      const row = line.match(/^\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|$/);
      if (row && row[1].trim() !== 'Package' && !row[1].trim().startsWith('-')) {
        const cwe = parseCwe(row[3]);
        report.npmAudit.push({
          pkg: row[1].trim(),
          severity: severityFromText(row[2]),
          cwe: cwe?.cwe || null,
          cweUrl: cwe?.url || null,
          fixAvailable: /yes/i.test(row[4]),
          autoFixable: /yes/i.test(row[5]),
        });
      }
      continue;
    }

    if (state === 'files scanned' && line.startsWith('|')) {
      const row = line.match(/^\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(\d+)\s*\|$/);
      if (row && row[1] !== 'Engine' && !/^-\s*$/.test(row[1])) {
        report.engines.push({ name: row[1].trim(), status: row[2].trim(), findings: parseInt(row[3], 10) });
      }
      continue;
    }
  }

  finishFinding();
  flushBlock();
  return report;
}

// ---------- render ----------

function pill(sev) {
  return `<span class="pill ${sev}">${SEVERITY_LABEL[sev]}</span>`;
}

function engineChip(name) {
  const cls = name === 'eslint' ? 'engine-eslint' : name === 'semgrep' ? 'engine-semgrep' : 'engine-npm';
  return `<span class="chip ${cls}">${ENGINE_META[name]?.label || name}</span>`;
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function findingCard(f, evidence) {
  const sev = f.severity || 'info';
  const loc = `${escapeHtml(normalizeFile(f.file || '') + (f.line ? ':' + f.line : ''))}`;
  const cwe = f.cweUrl
    ? `<a class="chip" href="${escapeHtml(f.cweUrl)}" target="_blank" rel="noopener">${escapeHtml(f.cwe)} ↗</a>`
    : f.cwe ? `<span class="chip">${escapeHtml(f.cwe)}</span>` : '';

  let evidenceHtml = '';
  if (evidence && evidence.lines.length) {
    evidenceHtml = `
      <div class="block evidence">
        <div class="block-label">Evidencia (código del sample)</div>
        <pre>${evidence.lines.map((l) =>
          `<span class="line${l.num === evidence.highlight ? ' highlight' : ''}"><span class="ln">${l.num}</span>${escapeHtml(l.text)}</span>`
        ).join('')}</pre>
      </div>`;
  }

  return `
    <article class="finding">
      <div class="finding-top">
        ${pill(sev)}
        <div class="finding-title">
          <p class="finding-message">${escapeHtml(f.message)}</p>
          <span class="finding-loc">${loc}</span>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-start;justify-content:flex-end;">
          ${engineChip(f.engine)}
          ${f.rule ? `<span class="chip" title="${escapeHtml(f.rule)}">${escapeHtml(shortRule(f.rule))}</span>` : ''}
          ${cwe}
        </div>
      </div>
      <div class="finding-body">
        <div class="block"><div class="block-label">Explicación</div><div class="block-text">${escapeHtml(f.explanation)}</div></div>
        <div class="block"><div class="block-label">Sugerencia de fix</div><div class="block-text">${escapeHtml(f.suggestion)}</div></div>
        ${evidenceHtml}
      </div>
    </article>`;
}

function shortRule(rule) {
  const cleaned = rule.replace(/^npm-audit\//, '');
  const parts = cleaned.split('.');
  return parts[parts.length - 1];
}

function groupSection(title, findings, evidenceMap, opts = {}) {
  const body = findings.map((f) => findingCard(f, evidenceMap.get(f))).join('');
  if (opts.collapsible) {
    return `
      <details class="medlow">
        <summary>${title} (${findings.length})</summary>
        <div class="details-body">${body}</div>
      </details>`;
  }
  return `
    <div class="findings-group">
      <div class="group-head">
        <h3>${title}</h3>
        <span class="group-count">${findings.length}</span>
      </div>
      ${body}
    </div>`;
}

function renderMeta(meta) {
  const items = [
    ['Repo', meta.repo],
    ['Branch', meta.branch],
    ['Commit', meta.commit],
    ['Scan path', meta.scanPath],
    ['Fecha', meta.date],
  ].filter(([, v]) => v);
  $('#meta-bar').innerHTML = items
    .map(([k, v]) => `<div class="meta-item"><b>${k}:</b><span>${escapeHtml(v)}</span></div>`)
    .join('');
  $('#meta-bar').hidden = false;
}

function renderWarnings(warnings) {
  if (!warnings.length) return;
  const caution = warnings.filter((w) => w.type === 'caution');
  const warning = warnings.filter((w) => w.type === 'warning');
  const html = [
    ...caution.map((w) => `<div class="warn warn-caution">⚠️ ${escapeHtml(w.lines.join(' ').replace(/\*\*/g, ''))}</div>`),
    ...warning.map((w) => `<div class="warn warn-warning">⚠️ ${escapeHtml(w.lines.join(' ').replace(/\*\*/g, ''))}</div>`),
  ].join('');
  $('#warnings').innerHTML = html;
  $('#warnings').hidden = false;
}

function renderSummary(summary) {
  const cards = [
    { key: 'total', label: 'Total' },
    { key: 'critical', label: 'Críticos' },
    { key: 'high', label: 'Altos' },
    { key: 'medium', label: 'Medios' },
    { key: 'low', label: 'Bajos' },
  ].map(({ key, label }) => {
    const extra = key === 'total' ? ' card-total' : ` card-${key}`;
    return `<div class="card${extra}"><div class="card-label">${label}</div><div class="card-value">${summary[key]}</div></div>`;
  });
  $('#summary-cards').innerHTML = cards.join('');
}

function renderEngines(engines) {
  if (!engines.length) return;
  $('#engines').innerHTML = engines.map((e) => {
    const meta = ENGINE_META[e.name] || { label: e.name, desc: '' };
    const ok = e.status.toUpperCase() === 'OK';
    return `
      <div class="engine-card">
        <div>
          <div class="engine-name">${meta.label}</div>
          <div class="engine-desc">${meta.desc}</div>
        </div>
        <div class="engine-status ${ok ? 'ok' : 'failed'}">
          <span class="dot"></span>
          ${ok ? 'OK' : 'FALLÓ'} · ${e.findings}
        </div>
      </div>`;
  }).join('');
}

function renderNpm(npm) {
  if (!npm.length) return;
  $('#npm-section').hidden = false;
  const rows = npm.map((r) => `
    <tr>
      <td>${escapeHtml(r.pkg)}</td>
      <td>${pill(r.severity)}</td>
      <td>${r.cweUrl ? `<a href="${escapeHtml(r.cweUrl)}" target="_blank" rel="noopener">${escapeHtml(r.cwe)} ↗</a>` : (r.cwe ? escapeHtml(r.cwe) : 'N/A')}</td>
      <td>${r.fixAvailable ? 'Sí' : 'No'}</td>
      <td>${r.autoFixable ? 'Sí' : 'No'}</td>
    </tr>`).join('');
  $('#npm-table').innerHTML = `
    <thead><tr><th>Paquete</th><th>Severidad</th><th>CVE / CWE</th><th>Fix disponible</th><th>Auto-fix</th></tr></thead>
    <tbody>${rows}</tbody>`;
}

// ---------- evidencia de código ----------

async function fetchEvidence(report) {
  const cache = new Map();
  const wanted = new Map(); // normalizedFile -> Set(line numbers)
  for (const f of report.findings) {
    if (!f.file || !f.line || f.line <= 0) continue;
    const norm = normalizeFile(f.file);
    if (!wanted.has(norm)) wanted.set(norm, new Set());
    wanted.get(norm).add(f.line);
  }

  const sources = new Map();
  await Promise.all([...wanted.keys()].map(async (file) => {
    try {
      const res = await fetch(file, { cache: 'no-store' });
      if (!res.ok) return;
      const text = await res.text();
      sources.set(file, text.split('\n'));
    } catch { /* sin evidencia si no se puede leer */ }
  }));

  const evidenceMap = new Map();
  for (const f of report.findings) {
    if (!f.file || !f.line || f.line <= 0) continue;
    const norm = normalizeFile(f.file);
    const src = sources.get(norm);
    if (!src) continue;
    const start = Math.max(1, f.line - 3);
    const end = Math.min(src.length, f.line + 2);
    const lines = [];
    for (let i = start; i <= end; i++) {
      lines.push({ num: i, text: src[i - 1] ?? '' });
    }
    evidenceMap.set(f, { lines, highlight: f.line });
  }
  return evidenceMap;
}

// ---------- main ----------

async function main() {
  let md;
  try {
    const res = await fetch(REPORT_PATH, { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    md = await res.text();
  } catch (err) {
    $('#findings').innerHTML = `
      <div class="error-box">
        No se pudo cargar <code>${REPORT_PATH}</code> (${escapeHtml(err.message)}).
        El reporte lo genera el workflow <code>auditguard.yml</code> al escanear <code>sample/</code>.
      </div>`;
    return;
  }

  const report = parseReport(md);
  const evidenceMap = await fetchEvidence(report);

  renderMeta(report.meta);
  renderWarnings(report.warnings);
  renderSummary(report.summary);
  renderEngines(report.engines);
  renderNpm(report.npmAudit);

  const bySeverity = { critical: [], high: [], medium: [], low: [], info: [] };
  for (const f of report.findings) {
    (bySeverity[f.severity] || bySeverity.info).push(f);
  }

  $('#findings').innerHTML = [
    bySeverity.critical.length ? groupSection('Hallazgos críticos', bySeverity.critical, evidenceMap) : '',
    bySeverity.high.length ? groupSection('Hallazgos altos', bySeverity.high, evidenceMap) : '',
    bySeverity.medium.length ? groupSection('Hallazgos medios', bySeverity.medium, evidenceMap, { collapsible: true }) : '',
    (bySeverity.low.length + bySeverity.info.length)
      ? groupSection('Hallazgos bajos e informativos', [...bySeverity.low, ...bySeverity.info], evidenceMap, { collapsible: true })
      : '',
  ].join('');

  $('#findings-section').hidden = !report.findings.length;
}

export { parseReport, normalizeFile };

if (typeof document !== 'undefined') main();
