// ============================================================================
// AuditGuard demo sample — código INTENCIONALMENTE vulnerable.
// Este proyecto es solo para demostrar el reporte de AuditGuard.
// NO usar en producción. NO copiar patrones de este archivo.
// ============================================================================

'use strict';

const express = require('express');
const crypto = require('crypto');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const db = require('./db');

const app = express();
app.use(express.json());

// --- CRÍTICO: RCE vía eval() con input del usuario (CWE-95) -----------------
// eslint-disable-next-line no-eval
app.post('/calculator', (req, res) => {
  const expression = req.body.expression;
  const result = eval(expression);
  res.json({ result });
});

// --- ALTO: inyección de comandos vía child_process.exec (CWE-78) ------------
app.post('/ping', (req, res) => {
  const host = req.body.host;
  exec('ping -c 1 ' + host, (error, stdout) => {
    if (error) return res.status(500).send(error.message);
    res.send(stdout);
  });
});

// --- CRÍTICO: token secreto hardcodeado en el código (CWE-798) --------------
const API_SECRET_TOKEN = 't9qXv4nLzKp2mRw8cYh7sBd0fGj3uIe6aNoQkWbCxV1S5D';
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

// --- MEDIO: comparación no constante → timing attack (CWE-208) --------------
app.post('/login', (req, res) => {
  const provided = req.body.token;
  const expected = process.env.SESSION_TOKEN || 'demo-token';
  if (provided === expected) {
    res.json({ ok: true });
  } else {
    res.status(401).json({ ok: false });
  }
});

// --- MEDIO: inyección de objeto / prototype pollution (CWE-1321) ------------
app.post('/settings', (req, res) => {
  const key = req.body.key;
  const value = req.body.value;
  const settings = {};
  settings[key] = value;
  res.json(settings);
});

// --- ALTO: path traversal con nombre de archivo no literal (CWE-22) ---------
app.get('/file', (req, res) => {
  const fileName = req.query.name;
  fs.readFile(fileName, 'utf8', (err, data) => {
    if (err) return res.status(500).send('Error');
    res.send(data);
  });
});

// --- MEDIO: RegExp construido con input del usuario → ReDoS (CWE-1333) ------
app.get('/search', (req, res) => {
  const pattern = req.query.pattern;
  const re = new RegExp(pattern);
  res.json({ matches: re.test(req.query.text || '') });
});

// --- ALTO: new Function() compilando string del usuario (CWE-94) ------------
app.post('/compile', (req, res) => {
  const code = req.body.code;
  const fn = new Function('return ' + code);
  res.json({ result: fn() });
});

// --- MEDIO: setTimeout con string → eval implícito (CWE-95) -----------------
app.post('/schedule', (req, res) => {
  const task = req.body.task;
  setTimeout('runTask("' + task + '")', 1000);
  res.json({ scheduled: true });
});

// --- MEDIO: Math.random() para token de seguridad (CWE-330) -----------------
function generateResetToken() {
  return Math.random().toString(36).slice(2);
}

// --- MEDIO: pseudoRandomBytes no criptográfico (CWE-330) ---------------------
function generateCsrfToken() {
  return crypto.pseudoRandomBytes(16).toString('hex');
}

// --- ALTO: new Buffer() deprecado (CWE-120) ---------------------------------
function wrapBuffer(data) {
  const buf = new Buffer(data);
  return buf.toString('base64');
}

// --- ALTO: XSS por innerHTML con input del usuario (CWE-79) ------------------
function renderProfile(name) {
  const el = document.getElementById('profile');
  el.innerHTML = name;
}

// --- MEDIO: acceso a propiedades con clave de usuario (CWE-1321) ------------
app.post('/store', (req, res) => {
  const store = { config: { theme: 'dark' } };
  const section = req.body.section;
  const value = req.body.value;
  store.config[section] = value;
  res.json(store);
});

// --- ALTO: SQL injection por concatenación (CWE-89) --------------------------
app.get('/users', (req, res) => {
  const id = req.query.id;
  db.query('SELECT * FROM users WHERE id = ' + id, (err, rows) => {
    if (err) return res.status(500).send(err.message);
    res.json(rows);
  });
});

// --- ALTO: URL de redirect no validada → open redirect (CWE-601) ------------
app.get('/redirect', (req, res) => {
  const next = req.query.next;
  res.redirect(next);
});

// --- ALTO: no-script-url — javascript: URL (CWE-79) --------------------------
function navigate() {
  window.location = 'javascript:alert("logged in")';
}

// --- MEDIO: URL de fetch construida con input del usuario (SSRF) ------------
app.get('/proxy', (req, res) => {
  const target = req.query.url;
  fetch(target)
    .then((r) => r.text())
    .then((body) => res.send(body));
});

app.listen(3000, () => {
  console.log('auditguard-demo-sample listening on port 3000');
});
