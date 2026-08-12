# AuditGuard Security Report

**Repo:** rodricastanio/auditguard-demo
**Branch:** main
**Commit:** 16975ef
**Scan path:** `./sample`
**Date:** 2026-08-12T04:38:32.309Z

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 6 |
| 🟠 HIGH | 13 |
| 🟡 MEDIUM | 11 |
| 🔵 LOW | 1 |
| **Total** | **31** |

> [!CAUTION]
> **6 CRITICAL finding(s) detected.** CI will fail until resolved.

## Critical Findings

### eslint-security/detect-eval-with-expression-/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:23 — eval with argument of type Identifier

| Field | Value |
|-------|------|
| **Severity** | 🔴 CRITICAL |
| **File** | `/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:23` |
| **Rule** | `security/detect-eval-with-expression` |
| **CWE** | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) |
| **Engine** | eslint |

**Explanation:** eval() executes arbitrary code from a string. If the argument comes from user input, this is a Remote Code Execution (RCE) vulnerability.

**Suggestion:** Replace with a safe parser like JSON.parse() or a sandboxed evaluation library (e.g., isolated-vm).


---

### eslint-no-eval-/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:23 — eval can be harmful.

| Field | Value |
|-------|------|
| **Severity** | 🔴 CRITICAL |
| **File** | `/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:23` |
| **Rule** | `no-eval` |
| **CWE** | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) |
| **Engine** | eslint |

**Explanation:** eval() executes arbitrary code from a string, which is a Remote Code Execution vulnerability.

**Suggestion:** Remove eval() usage. Use JSON.parse() for data parsing or a sandboxed evaluation library.


---

### eslint-no-secrets/no-secrets-/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:37 — Found a string with entropy 5.52 : "t9qXv4nLzKp2mRw8cYh7sBd0fGj3uIe6aNoQkWbCxV1S5D"

| Field | Value |
|-------|------|
| **Severity** | 🔴 CRITICAL |
| **File** | `/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:37` |
| **Rule** | `no-secrets/no-secrets` |
| **CWE** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| **Engine** | eslint |

**Explanation:** Hardcoded secrets (API keys, tokens, passwords) in source code can be extracted by anyone with repository access.

**Suggestion:** Move secrets to environment variables or a secrets manager. Add the secret to .env.example with a placeholder.


---

### eslint-no-secrets/no-secrets-/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:38 — Found a string that matches "AWS API Key" : "AKIAIOSFODNN7EXAMPLE"

| Field | Value |
|-------|------|
| **Severity** | 🔴 CRITICAL |
| **File** | `/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:38` |
| **Rule** | `no-secrets/no-secrets` |
| **CWE** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| **Engine** | eslint |

**Explanation:** Hardcoded secrets (API keys, tokens, passwords) in source code can be extracted by anyone with repository access.

**Suggestion:** Move secrets to environment variables or a secrets manager. Add the secret to .env.example with a placeholder.


---

### eslint-no-secrets/no-secrets-/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:39 — Found a string with entropy 4.45 : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

| Field | Value |
|-------|------|
| **Severity** | 🔴 CRITICAL |
| **File** | `/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:39` |
| **Rule** | `no-secrets/no-secrets` |
| **CWE** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| **Engine** | eslint |

**Explanation:** Hardcoded secrets (API keys, tokens, passwords) in source code can be extracted by anyone with repository access.

**Suggestion:** Move secrets to environment variables or a secrets manager. Add the secret to .env.example with a placeholder.


---

### npm-audit-1097678-minimist — Prototype Pollution in minimist in minimist (1.0.0 - 1.2.5)

| Field | Value |
|-------|------|
| **Severity** | 🔴 CRITICAL |
| **File** | `package.json:0` |
| **Rule** | `npm-audit/minimist` |
| **CWE** | [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html) |
| **Engine** | npm-audit |

**Explanation:** Prototype Pollution in minimist. Vulnerability range: 1.0.0 - 1.2.5. https://github.com/advisories/GHSA-xvch-5gv4-984h

**Suggestion:** Run 'npm audit fix' to update minimist to a patched version.


---

## High Findings

### eslint-security/detect-child-process-/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:30 — Found child\_process.exec() with non Literal first argument

| Field | Value |
|-------|------|
| **Severity** | 🟠 HIGH |
| **File** | `/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:30` |
| **Rule** | `security/detect-child-process` |
| **CWE** | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) |
| **Engine** | eslint |

**Explanation:** child_process.exec() with a non-literal argument allows command injection if the argument is user-controlled.

**Suggestion:** Use execFile() with an array of arguments, or use a library like cross-spawn with proper escaping.


---

### eslint-security/detect-non-literal-fs-filename-/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:64 — Found readFile from package "fs" with non literal argument at index 0

| Field | Value |
|-------|------|
| **Severity** | 🟠 HIGH |
| **File** | `/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:64` |
| **Rule** | `security/detect-non-literal-fs-filename` |
| **CWE** | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| **Engine** | eslint |

**Explanation:** File system operations with variable filenames can lead to path traversal attacks if the filename is user-controlled.

**Suggestion:** Validate and sanitize file paths. Use path.resolve() and verify the result is within the expected directory.


---

### eslint-no-new-func-/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:80 — The Function constructor is eval.

| Field | Value |
|-------|------|
| **Severity** | 🟠 HIGH |
| **File** | `/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:80` |
| **Rule** | `no-new-func` |
| **CWE** | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) |
| **Engine** | eslint |

**Explanation:** new Function() compiles a string into code, which is equivalent to eval().

**Suggestion:** Use a predefined function or a safe evaluation library.


---

### eslint-security/detect-new-buffer-/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:103 — Found new Buffer

| Field | Value |
|-------|------|
| **Severity** | 🟠 HIGH |
| **File** | `/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:103` |
| **Rule** | `security/detect-new-buffer` |
| **CWE** | [CWE-120](https://cwe.mitre.org/data/definitions/120.html) |
| **Engine** | eslint |

**Explanation:** new Buffer() is deprecated and can lead to buffer overflow vulnerabilities.

**Suggestion:** Use Buffer.alloc(), Buffer.from(), or Buffer.allocUnsafe() instead.


---

### eslint-no-script-url-/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:139 — Script URL is a form of eval.

| Field | Value |
|-------|------|
| **Severity** | 🟠 HIGH |
| **File** | `/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:139` |
| **Rule** | `no-script-url` |
| **CWE** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| **Engine** | eslint |

**Explanation:** javascript: URLs execute code in the context of the page, which can lead to XSS.

**Suggestion:** Use event handlers or navigation methods instead of javascript: URLs.


---

### eslint-security/detect-non-literal-require-/home/runner/work/auditguard-demo/auditguard-demo/sample/src/db.js:19 — Found non-literal argument in require

| Field | Value |
|-------|------|
| **Severity** | 🟠 HIGH |
| **File** | `/home/runner/work/auditguard-demo/auditguard-demo/sample/src/db.js:19` |
| **Rule** | `security/detect-non-literal-require` |
| **CWE** | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) |
| **Engine** | eslint |

**Explanation:** require() with a variable argument can load arbitrary modules, leading to code execution.

**Suggestion:** Use a static require() with a literal string, or validate the module name against an allowlist.


---

### semgrep-javascript.lang.security.audit.code-string-concat.code-string-concat-sample/src/app.js:23 — Found data from an Express or Next web request flowing to \`eval\`. If this data is user-controllable this can lead to execution of arbitrary system commands in the context of your application process. Avoid \`eval\` whenever possible.

| Field | Value |
|-------|------|
| **Severity** | 🟠 HIGH |
| **File** | `sample/src/app.js:23` |
| **Rule** | `javascript.lang.security.audit.code-string-concat.code-string-concat` |
| **CWE** | [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html) |
| **Engine** | semgrep |

**Explanation:** Found data from an Express or Next web request flowing to `eval`. If this data is user-controllable this can lead to execution of arbitrary system commands in the context of your application process. Avoid `eval` whenever possible.

**Suggestion:** Review the flagged code and apply security best practices.


---

### semgrep-javascript.lang.security.detect-child-process.detect-child-process-sample/src/app.js:30 — Detected calls to child\_process from a function argument \`req\`. This could lead to a command injection if the input is user controllable. Try to avoid calls to child\_process, and if it is needed ensure user input is correctly sanitized or sandboxed. 

| Field | Value |
|-------|------|
| **Severity** | 🟠 HIGH |
| **File** | `sample/src/app.js:30` |
| **Rule** | `javascript.lang.security.detect-child-process.detect-child-process` |
| **CWE** | [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html) |
| **Engine** | semgrep |

**Explanation:** Detected calls to child_process from a function argument `req`. This could lead to a command injection if the input is user controllable. Try to avoid calls to child_process, and if it is needed ensure user input is correctly sanitized or sandboxed. 

**Suggestion:** Review the flagged code and apply security best practices.


---

### semgrep-javascript.express.security.audit.remote-property-injection.remote-property-injection-sample/src/app.js:57 — Bracket object notation with user input is present, this might allow an attacker to access all properties of the object and even it's prototype. Use literal values for object properties.

| Field | Value |
|-------|------|
| **Severity** | 🟠 HIGH |
| **File** | `sample/src/app.js:57` |
| **Rule** | `javascript.express.security.audit.remote-property-injection.remote-property-injection` |
| **CWE** | [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html) |
| **Engine** | semgrep |

**Explanation:** Bracket object notation with user input is present, this might allow an attacker to access all properties of the object and even it's prototype. Use literal values for object properties.

**Suggestion:** Review the flagged code and apply security best practices.


---

### semgrep-javascript.express.security.audit.remote-property-injection.remote-property-injection-sample/src/app.js:118 — Bracket object notation with user input is present, this might allow an attacker to access all properties of the object and even it's prototype. Use literal values for object properties.

| Field | Value |
|-------|------|
| **Severity** | 🟠 HIGH |
| **File** | `sample/src/app.js:118` |
| **Rule** | `javascript.express.security.audit.remote-property-injection.remote-property-injection` |
| **CWE** | [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html) |
| **Engine** | semgrep |

**Explanation:** Bracket object notation with user input is present, this might allow an attacker to access all properties of the object and even it's prototype. Use literal values for object properties.

**Suggestion:** Review the flagged code and apply security best practices.


---

### npm-audit-1106913-lodash — Command Injection in lodash in lodash (\<=4.17.23)

| Field | Value |
|-------|------|
| **Severity** | 🟠 HIGH |
| **File** | `package.json:0` |
| **Rule** | `npm-audit/lodash` |
| **CWE** | [CWE-77](https://cwe.mitre.org/data/definitions/77.html) |
| **Engine** | npm-audit |

**Explanation:** Command Injection in lodash. Vulnerability range: <=4.17.23. https://github.com/advisories/GHSA-35jh-r3h4-6jhm

**Suggestion:** Run 'npm audit fix' to update lodash to a patched version.


---

### npm-audit-1096485-minimatch — minimatch ReDoS vulnerability in minimatch (\<=3.1.3)

| Field | Value |
|-------|------|
| **Severity** | 🟠 HIGH |
| **File** | `package.json:0` |
| **Rule** | `npm-audit/minimatch` |
| **CWE** | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) |
| **Engine** | npm-audit |

**Explanation:** minimatch ReDoS vulnerability. Vulnerability range: <=3.1.3. https://github.com/advisories/GHSA-f8q6-p94x-37v3

**Suggestion:** Run 'npm audit fix' to update minimatch to a patched version.


---

### npm-audit-1095073-node-fetch — node-fetch forwards secure headers to untrusted sites in node-fetch (\<2.6.7)

| Field | Value |
|-------|------|
| **Severity** | 🟠 HIGH |
| **File** | `package.json:0` |
| **Rule** | `npm-audit/node-fetch` |
| **CWE** | [CWE-173](https://cwe.mitre.org/data/definitions/173.html) |
| **Engine** | npm-audit |

**Explanation:** node-fetch forwards secure headers to untrusted sites. Vulnerability range: <2.6.7. https://github.com/advisories/GHSA-r683-j2x4-v87g

**Suggestion:** Run 'npm audit fix' to update node-fetch to a patched version.


---

<details>
<summary>Medium Findings (11)</summary>

### eslint-security/detect-object-injection-/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:57 — Generic Object Injection Sink

| Field | Value |
|-------|------|
| **Severity** | 🟡 MEDIUM |
| **File** | `/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:57` |
| **Rule** | `security/detect-object-injection` |
| **CWE** | [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html) |
| **Engine** | eslint |

**Explanation:** Using user-controlled keys to access object properties can lead to prototype pollution.

**Suggestion:** Use Object.create(null) for dictionaries, or validate keys against an allowlist.


### eslint-security/detect-non-literal-regexp-/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:73 — Found non-literal argument to RegExp Constructor

| Field | Value |
|-------|------|
| **Severity** | 🟡 MEDIUM |
| **File** | `/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:73` |
| **Rule** | `security/detect-non-literal-regexp` |
| **CWE** | [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html) |
| **Engine** | eslint |

**Explanation:** Constructing a RegExp from a variable allows an attacker to inject arbitrary patterns, potentially causing ReDoS.

**Suggestion:** Use literal regular expressions or validate the input against an allowlist of patterns.


### eslint-security/detect-pseudoRandomBytes-/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:98 — Found crypto.pseudoRandomBytes which does not produce cryptographically strong numbers

| Field | Value |
|-------|------|
| **Severity** | 🟡 MEDIUM |
| **File** | `/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:98` |
| **Rule** | `security/detect-pseudoRandomBytes` |
| **CWE** | [CWE-330](https://cwe.mitre.org/data/definitions/330.html) |
| **Engine** | eslint |

**Explanation:** pseudoRandomBytes() is not cryptographically secure. It should not be used for security-sensitive operations.

**Suggestion:** Use crypto.randomBytes() or crypto.randomUUID() for cryptographic randomness.


### eslint-security/detect-object-injection-/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:118 — Generic Object Injection Sink

| Field | Value |
|-------|------|
| **Severity** | 🟡 MEDIUM |
| **File** | `/home/runner/work/auditguard-demo/auditguard-demo/sample/src/app.js:118` |
| **Rule** | `security/detect-object-injection` |
| **CWE** | [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html) |
| **Engine** | eslint |

**Explanation:** Using user-controlled keys to access object properties can lead to prototype pollution.

**Suggestion:** Use Object.create(null) for dictionaries, or validate keys against an allowlist.


### semgrep-javascript.browser.security.eval-detected.eval-detected-sample/src/app.js:23 — Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.

| Field | Value |
|-------|------|
| **Severity** | 🟡 MEDIUM |
| **File** | `sample/src/app.js:23` |
| **Rule** | `javascript.browser.security.eval-detected.eval-detected` |
| **CWE** | [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html) |
| **Engine** | semgrep |

**Explanation:** Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.

**Suggestion:** Review the flagged code and apply security best practices.


### semgrep-javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp-sample/src/app.js:73 — RegExp() called with a \`req\` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

| Field | Value |
|-------|------|
| **Severity** | 🟡 MEDIUM |
| **File** | `sample/src/app.js:73` |
| **Rule** | `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp` |
| **CWE** | [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html) |
| **Engine** | semgrep |

**Explanation:** RegExp() called with a `req` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

**Suggestion:** Review the flagged code and apply security best practices.


### semgrep-javascript.lang.security.detect-pseudorandombytes.detect-pseudoRandomBytes-sample/src/app.js:98 — Detected usage of crypto.pseudoRandomBytes, which does not produce secure random numbers.

| Field | Value |
|-------|------|
| **Severity** | 🟡 MEDIUM |
| **File** | `sample/src/app.js:98` |
| **Rule** | `javascript.lang.security.detect-pseudorandombytes.detect-pseudoRandomBytes` |
| **CWE** | [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html) |
| **Engine** | semgrep |

**Explanation:** Detected usage of crypto.pseudoRandomBytes, which does not produce secure random numbers.

**Suggestion:** Review the flagged code and apply security best practices.


### semgrep-javascript.express.security.audit.possible-user-input-redirect.unknown-value-in-redirect-sample/src/app.js:134 — It looks like 'next' is read from user input and it is used to as a redirect. Ensure 'next' is not externally controlled, otherwise this is an open redirect.

| Field | Value |
|-------|------|
| **Severity** | 🟡 MEDIUM |
| **File** | `sample/src/app.js:134` |
| **Rule** | `javascript.express.security.audit.possible-user-input-redirect.unknown-value-in-redirect` |
| **CWE** | [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html) |
| **Engine** | semgrep |

**Explanation:** It looks like 'next' is read from user input and it is used to as a redirect. Ensure 'next' is not externally controlled, otherwise this is an open redirect.

**Suggestion:** Review the flagged code and apply security best practices.


### semgrep-javascript.express.security.audit.express-open-redirect.express-open-redirect-sample/src/app.js:134 — The application redirects to a URL specified by user-supplied input \`req\` that is not validated. This could redirect users to malicious locations. Consider using an allow-list approach to validate URLs, or warn users they are being redirected to a third-party website.

| Field | Value |
|-------|------|
| **Severity** | 🟡 MEDIUM |
| **File** | `sample/src/app.js:134` |
| **Rule** | `javascript.express.security.audit.express-open-redirect.express-open-redirect` |
| **CWE** | [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html) |
| **Engine** | semgrep |

**Explanation:** The application redirects to a URL specified by user-supplied input `req` that is not validated. This could redirect users to malicious locations. Consider using an allow-list approach to validate URLs, or warn users they are being redirected to a third-party website.

**Suggestion:** Review the flagged code and apply security best practices.


### semgrep-javascript.lang.security.audit.md5-used-as-password.md5-used-as-password-sample/src/db.js:25 — It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function such as bcrypt. You can use the \`bcrypt\` node.js package.

| Field | Value |
|-------|------|
| **Severity** | 🟡 MEDIUM |
| **File** | `sample/src/db.js:25` |
| **Rule** | `javascript.lang.security.audit.md5-used-as-password.md5-used-as-password` |
| **CWE** | [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html) |
| **Engine** | semgrep |

**Explanation:** It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function such as bcrypt. You can use the `bcrypt` node.js package.

**Suggestion:** Review the flagged code and apply security best practices.


### npm-audit-1097679-axios — Axios Cross-Site Request Forgery Vulnerability in axios (\<=0.32.0)

| Field | Value |
|-------|------|
| **Severity** | 🟡 MEDIUM |
| **File** | `package.json:0` |
| **Rule** | `npm-audit/axios` |
| **CWE** | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) |
| **Engine** | npm-audit |

**Explanation:** Axios Cross-Site Request Forgery Vulnerability. Vulnerability range: <=0.32.0. https://github.com/advisories/GHSA-wf5p-g6vw-rhxx

**Suggestion:** Run 'npm audit fix' to update axios to a patched version.


</details>

<details>
<summary>Low/Info Findings (1)</summary>

### semgrep-javascript.express.security.audit.express-check-csurf-middleware-usage.express-check-csurf-middleware-usage-sample/src/app.js:16 — A CSRF middleware was not detected in your express application. Ensure you are either using one such as \`csurf\` or \`csrf\` (see rule references) and/or you are properly doing CSRF validation in your routes with a token or cookies.

| Field | Value |
|-------|------|
| **Severity** | 🔵 LOW |
| **File** | `sample/src/app.js:16` |
| **Rule** | `javascript.express.security.audit.express-check-csurf-middleware-usage.express-check-csurf-middleware-usage` |
| **CWE** | [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html) |
| **Engine** | semgrep |

**Explanation:** A CSRF middleware was not detected in your express application. Ensure you are either using one such as `csurf` or `csrf` (see rule references) and/or you are properly doing CSRF validation in your routes with a token or cookies.

**Suggestion:** Review the flagged code and apply security best practices.


</details>


---

## npm audit

| Package | Severity | CVE | Fix Available | Auto-fixable |
|---------|----------|-----|---------------|--------------|
| axios | MEDIUM | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | Yes | No |
| lodash | HIGH | [CWE-77](https://cwe.mitre.org/data/definitions/77.html) | Yes | Yes |
| minimatch | HIGH | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | Yes | Yes |
| minimist | CRITICAL | [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html) | Yes | Yes |
| node-fetch | HIGH | [CWE-173](https://cwe.mitre.org/data/definitions/173.html) | Yes | Yes |

---

## Files Scanned

| Engine | Status | Findings |
|--------|--------|----------|
| eslint | OK | 15 |
| semgrep | OK | 11 |
| npm-audit | OK | 5 |

---

*Generated by [AuditGuard](https://github.com/org/auditguard) v0.1.0*
