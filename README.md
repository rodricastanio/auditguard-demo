# AuditGuard Demo

Showcase de [AuditGuard](https://github.com/rodricastanio/AuditGuard) — GitHub Action de
seguridad que audita repos JS/TS con **ESLint + Semgrep + npm audit** y genera un reporte Markdown.

Esta demo es una página estática que renderiza el **reporte real** de AuditGuard, generado por el
propio workflow (`.github/workflows/auditguard.yml`) escaneando `sample/`, un proyecto
**intencionalmente vulnerable**.

## Estructura

```
.
├── index.html            # Página showcase (HTML/CSS/JS puro, en español)
├── styles.css            # Estilo "security dashboard" oscuro
├── renderer.js           # Renderiza report.md (parser del formato AuditGuard)
├── report.md             # Reporte GENERADO por AuditGuard (no escrito a mano)
├── sample/               # Proyecto intencionalmente vulnerable (la fuente de hallazgos)
│   ├── package.json      # Dependencias con CVEs reales (lodash, axios, minimist…)
│   └── src/              # Código con vulnerabilidades típicas (eval, XSS, SQLi…)
├── scripts/run-local.mjs # Ejecuta los engines de AuditGuard localmente
└── .github/workflows/auditguard.yml  # Workflow que regenera report.md
```

## Cómo se genera el reporte

1. El workflow `auditguard.yml` corre `rodricastanio/AuditGuard@main` con `scan-path: './sample'`.
2. Los 3 motores escanean el sample vulnerable y generan el reporte Markdown.
3. El reporte se guarda como `report.md` y se commitea de vuelta al repo.
4. La página lee `report.md` en runtime y lo renderiza (sin frameworks).

### Correr los engines localmente (Camino B)

```bash
git clone https://github.com/rodricastanio/AuditGuard ../auditGuard
cd ../auditGuard && npm install && npm run build
# opcional: instalar semgrep 1.170.1 (pip install semgrep==1.170.1)
node scripts/run-local.mjs
```

> En Windows, el engine `npm audit` puede fallar al invocar `npm` directamente
> (quirk de `execFile` con `npm` sh-script). En el runner de GitHub Actions corre sin problemas.

## Disclaimer

`sample/` contiene vulnerabilidades reales a propósito: `eval()`, inyección de comandos y SQL,
XSS, secretos hardcodeados y dependencias con CVEs conocidos. **No usar como referencia segura.**
