// ============================================================================
// AuditGuard demo sample — helper de "base de datos".
// NO usar en producción. No copiar patrones de este archivo.
// ============================================================================

'use strict';

const crypto = require('crypto');
const fs = require('fs');

// --- ALTO: inyección SQL con concatenación de strings (CWE-89) --------------
function query(sql, cb) {
  // Simula una consulta a una base de datos.
  setTimeout(() => cb(null, [{ result: sql }]), 5);
}

// --- MEDIO: nombre de archivo no literal en require (CWE-94) ----------------
function loadModule(moduleName) {
  const loaded = require(moduleName);
  return loaded;
}

// --- MEDIO: hash con algoritmo inseguro (MD5) --------------------------------
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// --- MEDIO: URL construida con input del usuario (SSRF) ----------------------
function fetchResource(resourcePath) {
  const url = 'https://api.example.com/v1/' + resourcePath;
  return fetch(url);
}

module.exports = { query, loadModule, hashPassword, fetchResource };
