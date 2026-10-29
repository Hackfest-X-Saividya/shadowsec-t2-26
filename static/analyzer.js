/* Language-neutral analyzer for "Zday Protocol".
 * Runs in the browser (and under node for tests). Never executes the code it reads:
 * it extracts functions, judges claim vs reality, scores CVSS 3.1, and predicts attacks.
 * Real execution lives in the Python sandbox (server.py) and only covers screened Python.
 */
(function (root) {
'use strict';

const USERS = [
  {id: 1, username: 'alice', email: 'alice@example.test'},
  {id: 2, username: 'bob', email: 'bob@example.test'},
  {id: 3, username: 'carol', email: 'carol@example.test'},
  {id: 4, username: 'dave', email: 'dave@example.test'},
  {id: 5, username: 'erin', email: 'erin@example.test'},
];
const KEYWORDS = ['sanitize', 'clean', 'escape', 'validate', 'verify', 'auth', 'hash', 'encrypt'];
const ATTACKS = {
  sqli_sanitizer: {label: 'SQL injection', payload: "' OR '1'='1", owasp: 'A03:2021 Injection',
    fix: 'Allow-list the input (or use parameterised queries) instead of passing it through unchanged.'},
  sqli_validator: {label: 'SQL injection through a validator that accepts everything', payload: "' OR '1'='1",
    owasp: 'A03:2021 Injection', fix: 'Validate against a strict allow-list pattern and reject anything else.'},
  fake_auth: {label: 'Forged session token', payload: 'forged-token-xyz',
    owasp: 'A07:2021 Identification and Authentication Failures',
    fix: 'Compare the token against stored sessions or a signature, using a constant-time comparison.'},
  weak_hash: {label: 'Rainbow-table lookup', payload: 'hunter2', owasp: 'A02:2021 Cryptographic Failures',
    fix: 'Use a salted, slow password hash such as PBKDF2, scrypt, bcrypt or Argon2.'},
};
const KIND_OF = {sanitizer: 'sqli_sanitizer', validator: 'sqli_validator', auth: 'fake_auth', crypto: 'weak_hash'};
const CVSS_METRICS = {
  sqli_sanitizer: {ac: 'L', pr: 'N', ui: 'N', c: 'H', i: 'H', a: 'N'},
  sqli_validator: {ac: 'L', pr: 'N', ui: 'N', c: 'H', i: 'H', a: 'N'},
  fake_auth: {ac: 'L', pr: 'N', ui: 'N', c: 'H', i: 'H', a: 'H'},
  weak_hash: {ac: 'H', pr: 'N', ui: 'N', c: 'H', i: 'N', a: 'N'},
};
const MODE_PRED = 'Simulated (predicted from static analysis, not executed)';
const MODE_REC = 'Real execution (recorded from the Python sandbox)';

const escRe = s => s.replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&');
const tokenIn = (text, tok) => new RegExp('(?<![\\w$])' + escRe(tok) + '(?![\\w])').test(text);
const normalize = s => String(s).replace(/\r\n/g, '\n').trim();

/* ------------------------------------------------------------------ CVSS / priority */
const W = {AV: {N: .85, A: .62, L: .55, P: .2}, AC: {L: .77, H: .44}, PR: {N: .85, L: .62, H: .27},
  UI: {N: .85, R: .62}, CIA: {H: .56, L: .22, N: 0}};
function roundup(x) { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; }
function cvss31(av, ac, pr, ui, c, i, a) {
  const iss = 1 - (1 - W.CIA[c]) * (1 - W.CIA[i]) * (1 - W.CIA[a]);
  const impact = 6.42 * iss, expl = 8.22 * W.AV[av] * W.AC[ac] * W.PR[pr] * W.UI[ui];
  return impact <= 0 ? 0 : roundup(Math.min(impact + expl, 10));
}
const band = s => s === 0 ? 'None' : s < 4 ? 'Low' : s < 7 ? 'Medium' : s < 9 ? 'High' : 'Critical';
function cvssFor(kind, reachable) {
  const m = CVSS_METRICS[kind], av = reachable ? 'N' : 'L';
  const score = cvss31(av, m.ac, m.pr, m.ui, m.c, m.i, m.a);
  return {score, band: band(score), vector: `CVSS:3.1/AV:${av}/AC:${m.ac}/PR:${m.pr}/UI:${m.ui}/S:U/C:${m.c}/I:${m.i}/A:${m.a}`};
}
function priority(b, exploit, status) {
  if (status === 'Verified') return 'Closed';
  const likely = exploit === 'confirmed', severe = b === 'Critical' || b === 'High';
  return severe && likely ? 'P1' : severe || (b === 'Medium' && likely) ? 'P2' : 'P3';
}
function likelihood(exploit, status) {
  if (exploit === 'confirmed') return 'Exploit proven in sandbox' + (status === 'Verified' ? ' (now blocked)' : '');
  if (String(exploit).startsWith('predicted')) return 'Predicted from static analysis, not executed';
  return 'Not tested. No CVE, so no EPSS.';
}
function category(name) {
  const n = name.toLowerCase();
  if (n.includes('hash') || n.includes('encrypt')) return 'crypto';
  if (n.includes('sanitize') || n.includes('clean') || n.includes('escape')) return 'sanitizer';
  if (n.includes('validate')) return 'validator';
  return 'auth';
}

/* ------------------------------------------------------------------ language detection */
const EXT = {py: 'python', js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript', ts: 'typescript',
  tsx: 'typescript', java: 'java', php: 'php', go: 'go', cs: 'csharp', rb: 'ruby'};
function detectLang(source, filename) {
  const m = /\.([a-z]+)$/i.exec(filename || '');
  if (m && EXT[m[1].toLowerCase()]) return EXT[m[1].toLowerCase()];
  if (/<\?php/.test(source)) return 'php';
  if (/^\s*package\s+\w+/m.test(source) && /\bfunc\s+/.test(source)) return 'go';
  if (/\b(public|private|protected)\s+(static\s+)?[\w<>\[\]]+\s+\w+\s*\(/.test(source))
    return /\bnamespace\b|\busing\s+System/.test(source) ? 'csharp' : 'java';
  if (/^\s*def\s+\w+.*:\s*$/m.test(source)) return 'python';
  if (/^\s*def\s+\w+/m.test(source) && /^\s*end\s*$/m.test(source)) return 'ruby';
  if (/\bfunction\b|=>/.test(source)) return 'javascript';
  return 'python';
}

/* ------------------------------------------------------------------ extraction */
const HASH_LANGS = new Set(['python', 'ruby', 'php']);
const SLASH_LANGS = new Set(['javascript', 'typescript', 'java', 'php', 'go', 'csharp']);
function stripComments(t, lang) {
  if (SLASH_LANGS.has(lang)) t = t.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:"'\\])\/\/.*$/gm, '$1');
  if (HASH_LANGS.has(lang)) t = t.replace(/(^|\s)#.*$/gm, '$1');
  return t;
}
function lineIndex(src) {
  const nl = []; for (let i = 0; i < src.length; i++) if (src.charCodeAt(i) === 10) nl.push(i);
  return idx => { let lo = 0, hi = nl.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (nl[mid] < idx) lo = mid + 1; else hi = mid; } return lo + 1; };
}
function findBlock(src, open) {
  let depth = 0, inStr = null;
  for (let i = open; i < src.length; i++) {
    const ch = src[i];
    if (inStr) { if (ch === '\\') { i++; continue; } if (ch === inStr) inStr = null; continue; }
    if (ch === '/' && src[i + 1] === '/') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (ch === '/' && src[i + 1] === '*') { const e = src.indexOf('*/', i + 2); i = e < 0 ? src.length : e + 1; continue; }
    if (ch === '/') {
      let k = i - 1; while (k >= 0 && (src[k] === ' ' || src[k] === '\t')) k--;
      if (k < 0 || '(,=:[!&|?{};\n'.includes(src[k]) || /\breturn$/.test(src.slice(Math.max(0, k - 6), k + 1))) {
        let j = i + 1, inClass = false;
        for (; j < src.length && src[j] !== '\n'; j++) {
          if (src[j] === '\\') { j++; continue; }
          if (src[j] === '[') inClass = true; else if (src[j] === ']') inClass = false;
          else if (src[j] === '/' && !inClass) break;
        }
        if (src[j] === '/') { i = j; continue; }
      }
    }
    if (ch === '"' || ch === "'" || ch === '`') { inStr = ch; continue; }
    if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth === 0) return i; }
  }
  return -1;
}
function parseParams(t, lang) {
  return (t || '').split(',').map(p => p.trim()).filter(Boolean).map(p => {
    p = p.replace(/=.*$/, '').trim();
    if (lang === 'typescript' || lang === 'javascript' || lang === 'python') p = p.split(':')[0].trim();
    p = p.replace(/^\*+|^\.\.\./, '').replace(/^&/, '');
    const tok = p.split(/\s+/).filter(Boolean);
    if (!tok.length) return null;
    return (lang === 'go' ? tok[0] : tok[tok.length - 1]).replace(/[?\[\]]/g, '').replace(/^\$/, '');
  }).filter(n => n && !['self', 'cls', 'this'].includes(n));
}
function above(lines, startIdx) {
  const comment = [], deco = [];
  for (let i = startIdx - 1; i >= 0; i--) {
    const t = lines[i].trim();
    if (!t) break;
    if (/^@/.test(t) || /^\[[A-Za-z]/.test(t)) deco.unshift(t);
    else if (/^(\/\/|#|\/\*|\*)/.test(t))
      comment.unshift(t.replace(/^(\/\/\/?|#+|\/\*\*?|\*\/|\*)\s?/, '').replace(/\*\/\s*$/, '').trim());
    else break;
  }
  return {comment: comment.filter(l => l && !/^@\w+/.test(l)).join(' '), deco};
}
const DEF_SKIP = new Set(['if', 'for', 'while', 'switch', 'catch', 'function', 'return', 'else', 'do', 'with', 'constructor', 'synchronized']);

function braceFuncs(src, lang) {
  const found = [], pats = [];
  if (lang === 'javascript' || lang === 'typescript') {
    pats.push(/\bfunction\s*\*?\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)[^{;]*\{/g);
    pats.push(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\s*[\w$]*\s*\(([^)]*)\)[^{;]*\{/g);
    pats.push(/^[ \t]*(?:(?:public|private|protected|static|async|get|set|readonly)\s+)*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*(?::\s*[^{;=]+)?\{/gm);
  } else if (lang === 'java' || lang === 'csharp') {
    pats.push(/^[ \t]*(?:(?:public|private|protected|static|final|abstract|synchronized|override|virtual|async|internal|sealed)[ \t]+)+(?:[\w<>\[\],.?]+[ \t]+)+([A-Za-z_]\w*)[ \t]*\(([^)]*)\)[^{;]*\{/gm);
  } else if (lang === 'php') {
    pats.push(/\bfunction\s+&?([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?::\s*\??[\w\\]+)?\s*\{/g);
  } else if (lang === 'go') {
    pats.push(/^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)[^{\n]*\{/gm);
  }
  for (const re of pats) {
    let m;
    while ((m = re.exec(src))) {
      if (DEF_SKIP.has(m[1])) continue;
      const open = m.index + m[0].length - 1, close = findBlock(src, open);
      if (close < 0) continue;
      found.push({name: m[1], paramsText: m[2], body: src.slice(open + 1, close), index: m.index});
    }
  }
  if (lang === 'javascript' || lang === 'typescript') {
    const arrow = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:\(([^)]*)\)|([A-Za-z_$][\w$]*))\s*(?::\s*[^=\n(]+?)?\s*=>\s*(\{)?/g;
    let m;
    while ((m = arrow.exec(src))) {
      let body;
      if (m[4]) {
        const open = m.index + m[0].length - 1, close = findBlock(src, open);
        if (close < 0) continue;
        body = src.slice(open + 1, close);
      } else {
        const i = m.index + m[0].length; let depth = 0, j = i;
        for (; j < src.length; j++) {
          const ch = src[j];
          if ('([{'.includes(ch)) depth++;
          else if (')]}'.includes(ch)) { if (depth === 0) break; depth--; }
          else if ((ch === ';' || ch === '\n') && depth === 0) break;
        }
        body = 'return ' + src.slice(i, j).trim();
      }
      found.push({name: m[1], paramsText: m[2] !== undefined ? m[2] : m[3], body, index: m.index});
    }
    const route = /\b(?:app|router|server)\.(?:get|post|put|delete|patch|all|use)\s*\(\s*(['"`])([^'"`]*)\1\s*,\s*(?:async\s+)?(?:function\s*\w*\s*)?\(?\s*([^)=]*?)\s*\)?\s*(?:=>)?\s*\{/g;
    while ((m = route.exec(src))) {
      const open = m.index + m[0].length - 1, close = findBlock(src, open);
      if (close < 0) continue;
      found.push({name: 'route:' + m[2], paramsText: m[3], body: src.slice(open + 1, close), index: m.index});
    }
  }
  return found;
}

function indentFuncs(src, lang) {
  const lines = src.split('\n'), out = [];
  const re = lang === 'python' ? /^([ \t]*)(?:async[ \t]+)?def[ \t]+([A-Za-z_]\w*)[ \t]*\(/ : /^([ \t]*)def[ \t]+(?:self\.)?([A-Za-z_]\w*[?!]?)/;
  const count = (s, c) => s.split(c).length - 1;
  let offset = 0; const starts = lines.map(l => { const o = offset; offset += l.length + 1; return o; });
  for (let i = 0; i < lines.length; i++) {
    const m = re.exec(lines[i]); if (!m) continue;
    const indent = m[1].replace(/\t/g, '    ').length;
    let header = lines[i], j = i, paramsText = '', bodyLines = [];
    if (lang === 'python') {
      let depth = count(header, '(') - count(header, ')');
      while (depth > 0 && j + 1 < lines.length) { j++; header += '\n' + lines[j]; depth += count(lines[j], '(') - count(lines[j], ')'); }
      const o = header.indexOf('('); let d = 0, c = o;
      for (; c < header.length; c++) { if (header[c] === '(') d++; else if (header[c] === ')') { d--; if (d === 0) break; } }
      paramsText = header.slice(o + 1, c);
      const colon = header.lastIndexOf(':'), rest = header.slice(colon + 1).trim();
      if (rest && !rest.startsWith('#')) bodyLines.push(rest);
      for (let k = j + 1; k < lines.length; k++) {
        const l = lines[k];
        if (l.trim() && l.search(/\S/) <= indent) break;
        bodyLines.push(l);
      }
    } else {
      const pm = /def[ \t]+(?:self\.)?[A-Za-z_]\w*[?!]?[ \t]*(?:\(([^)]*)\)|([^\n]*))/.exec(lines[i]);
      paramsText = pm ? (pm[1] !== undefined ? pm[1] : pm[2] || '') : '';
      for (let k = i + 1; k < lines.length; k++) {
        if (/^[ \t]*end\b/.test(lines[k]) && lines[k].search(/\S/) <= indent) break;
        bodyLines.push(lines[k]);
      }
    }
    out.push({name: m[2], paramsText, body: bodyLines.join('\n').replace(/\s+$/, ''), index: starts[i] + m[1].length});
  }
  return out;
}

function extract(source, lang) {
  const lines = source.split('\n'), lineOf = lineIndex(source);
  const raw = (lang === 'python' || lang === 'ruby') ? indentFuncs(source, lang) : braceFuncs(source, lang);
  const seen = new Set(), out = [];
  for (const f of raw) {
    const line = lineOf(f.index), key = f.name + ':' + line;
    if (seen.has(key)) continue; seen.add(key);
    const ab = above(lines, line - 1);
    let body = f.body, doc = '';
    const dm = lang === 'python' ? /^\s*(?:"""([\s\S]*?)"""|'''([\s\S]*?)''')\s*/.exec(body) : null;
    if (dm) { doc = (dm[1] || dm[2] || '').replace(/\s+/g, ' ').trim(); body = body.slice(dm[0].length); }
    out.push({name: f.name, line, params: parseParams(f.paramsText, lang), paramText: (f.paramsText || '').trim(),
      body, doc, comment: ab.comment, deco: ab.deco});
  }
  return out.sort((a, b) => a.line - b.line);
}

const HANDLER_PARAMS = new Set(['req', 'request', 'res', 'response', 'ctx', 'event', 'context', 'params', 'body', 'query']);
const isHandlerName = n => /^(handle|route:)/i.test(n);
function isHandler(f) {
  return /^(handle|route|view_|api_|endpoint|controller|serve)/i.test(f.name) || f.params.some(p => HANDLER_PARAMS.has(p)) ||
    f.deco.some(d => /route|mapping|\.get|\.post|\.put|\.delete|^@(get|post|put|delete)\b/i.test(d));
}
const claiming = funcs => funcs.filter(f => !isHandlerName(f.name) && KEYWORDS.some(k => f.name.toLowerCase().includes(k)));

/* ------------------------------------------------------------------ judge */
const SAN = /\b(replace|replaceAll|replace_all|replaceFirst|sub|gsub|escape|escapeHtml|encodeURI|encodeURIComponent|quote|quote_plus|translate|basename|fullmatch|match|matches|test|exec|htmlspecialchars|htmlentities|strip_tags|addslashes|preg_replace|preg_match|filter_var|real_escape_string|prepare|PreparedStatement|Pattern|Matcher|Regex|Regexp|sanitize|bleach|DOMPurify|isAlphanumeric)\b|\b(throw|raise|panic)\b/;
const VALID_STRUCT = /\b(if|unless|match|matches|test|regex|preg_match|throw|raise|panic|len|length|isNaN|isinstance|typeof|instanceof|fullmatch|isalnum|isdigit|isalpha)\b|[<>]=?|===?|!==?|\?/;
const ATOM = '(?:true|True|TRUE|!!\\$?\\w+|\\$?\\w+\\s+is\\s+not\\s+None|\\$?\\w+\\s*(?:!==?|!=|<>)\\s*(?:null|undefined|nil|None|NULL|false|""|\'\')|\\$?\\w+\\.length\\s*>\\s*0|len\\(\\$?\\w+\\)\\s*>\\s*0|!empty\\(\\$?\\w+\\)|!?\\$?\\w+(?:\\.|->)(?:isEmpty|isBlank)\\(\\)|len\\(\\$?\\w+\\)\\s*(?:!=|>)\\s*0|isset\\(\\$?\\w+\\)|bool\\(\\$?\\w+\\)|not\\s+\\$?\\w+\\s+is\\s+None)';
const WEAK_AUTH = new RegExp('^(?:return\\s+)?' + ATOM + '(?:\\s*(?:&&|\\|\\||\\band\\b|\\bor\\b)\\s*' + ATOM + ')*\\s*;?$');
const SLOW_KDF = /bcrypt|scrypt|argon2|pbkdf2|password_hash|hashpw/i;
const WEAK_HASH = /md5|sha-?1(?![0-9])/i;
const B64 = /btoa|base64|b64/i;

function judge(fn, lang) {
  const cat = category(fn.name);
  const claim = fn.doc || fn.comment || `${fn.name}() implies a security ${cat} step`;
  let body = stripComments(fn.body, lang).trim();
  const flat = body.replace(/\s+/g, ' ').trim();
  const verdict = (score, reality) => ({claim, reality, mismatch: score >= 50, lie_score: score,
    reason: score >= 50 ? `Claims: ${claim} Reality: ${reality}` : 'Behaviour matches the claim.'});
  const identity = fn.params.some(p => new RegExp('^(?:return\\s+)?\\$?' + escRe(p) + '\\s*;?$').test(flat));
  if (cat === 'sanitizer') {
    if (identity) return verdict(95, 'Returns its input unchanged. Nothing is removed or escaped.');
    if (!SAN.test(body)) return verdict(80, 'Only makes cosmetic changes. Quotes and other dangerous characters survive.');
    return verdict(5, 'Transforms or escapes the input.');
  }
  if (cat === 'validator') {
    if (/^(?:return\s+)?(?:true|True|TRUE|!0|1)\s*;?$/.test(flat)) return verdict(92, 'Always returns true. It never checks the input.');
    if (!VALID_STRUCT.test(body)) return verdict(75, 'Returns without checking the input against any rule.');
    return verdict(8, 'Checks the input against explicit rules.');
  }
  if (cat === 'auth') {
    if (flat.length < 400 && WEAK_AUTH.test(flat)) return verdict(90, 'Accepts any non-empty token. It is never compared with a stored session or signature.');
    return verdict(6, 'Compares the credential against a trusted value.');
  }
  if (SLOW_KDF.test(body)) return verdict(4, 'Uses a slow, salted key-derivation function.');
  if (WEAK_HASH.test(body)) return verdict(80, 'Uses MD5/SHA-1, a fast unsalted hash that precomputed tables crack instantly.');
  if (B64.test(body)) return verdict(90, 'Base64 is encoding, not encryption. Anyone can reverse it.');
  if (identity) return verdict(98, 'Returns its input unchanged.');
  if (/password/i.test(fn.name) && /sha-?(256|512)/i.test(body)) return verdict(60, 'Uses a fast unsalted hash for passwords.');
  return verdict(8, 'No weakness found by the rules.');
}

function reachability(funcs, target, lang) {
  const hits = [];
  for (const h of funcs) {
    if (h.name === target.name && h.line === target.line) continue;
    if (!isHandler(h)) continue;
    const tainted = new Set();
    [...h.params, 'request', 'req', 'params', 'body', '$_GET', '$_POST', '$_REQUEST'].forEach(s => { tainted.add(s); tainted.add('$' + s); });
    const text = stripComments(h.body, lang);
    for (let k = 0; k < 3; k++) {
      const re = /([$\w.]+)\s*(?::=|=)\s*([^\n;=][^\n;]*)/g; let m;
      while ((m = re.exec(text))) {
        for (const t of [...tainted]) if (tokenIn(m[2], t)) { tainted.add(m[1]); tainted.add(m[1].replace(/^\$/, '')); break; }
      }
    }
    const call = new RegExp('(?<![\\w$.])' + escRe(target.name) + '\\s*\\(([^)]*)\\)', 'g'); let m;
    while ((m = call.exec(text))) {
      const used = [...tainted].find(t => tokenIn(m[1], t));
      if (used) hits.push(`user input '${used.replace(/^\$/, '')}' enters ${h.name}() and reaches ${target.name}()`);
    }
  }
  return [...new Set(hits)];
}

/* ------------------------------------------------------------------ reference patches */
function referencePatch(lang, cat, fn) {
  const A = fn.paramText, P = fn.params[0] || 'value', N = fn.name;
  if (lang === 'python') return {
    sanitizer: `def ${N}(${A}):\n    """Allow-list sanitizer: keeps letters, digits, whitespace and @ . _ - only."""\n    import re\n    return re.sub(r"[^\\w\\s@.\\-]", "", str(${P}))\n`,
    validator: `def ${N}(${A}):\n    """Accepts only 1-32 letters, digits, dots, dashes and underscores."""\n    import re\n    return isinstance(${P}, str) and re.fullmatch(r"[A-Za-z0-9_.\\-]{1,32}", ${P}) is not None\n`,
    auth: `def ${N}(${A}):\n    """Accepts the token only if it matches an active session (constant-time compare)."""\n    import hmac\n    return isinstance(${P}, str) and any(hmac.compare_digest(${P}, t) for t in SESSIONS)\n`,
    crypto: `def ${N}(${A}):\n    """Salted PBKDF2-HMAC-SHA256 password hash (200k iterations)."""\n    import hashlib, secrets\n    salt = secrets.token_bytes(16)\n    dk = hashlib.pbkdf2_hmac("sha256", str(${P}).encode(), salt, 200_000)\n    return salt.hex() + "$" + dk.hex()\n`,
  }[cat];
  if (lang === 'javascript' || lang === 'typescript') return {
    sanitizer: `function ${N}(${A}) {\n  // Allow-list: keep letters, digits, whitespace and @ . _ - only\n  return String(${P}).replace(/[^\\w\\s@.\\-]/g, "");\n}\n`,
    validator: `function ${N}(${A}) {\n  return typeof ${P} === "string" && /^[A-Za-z0-9_.\\-]{1,32}$/.test(${P});\n}\n`,
    auth: `function ${N}(${A}) {\n  // SESSIONS: your store of active session tokens\n  const crypto = require("crypto");\n  return typeof ${P} === "string" && Object.keys(SESSIONS).some(t =>\n    t.length === ${P}.length && crypto.timingSafeEqual(Buffer.from(t), Buffer.from(${P})));\n}\n`,
    crypto: `function ${N}(${A}) {\n  const crypto = require("crypto");\n  const salt = crypto.randomBytes(16);\n  const dk = crypto.pbkdf2Sync(String(${P}), salt, 200000, 32, "sha256");\n  return salt.toString("hex") + "$" + dk.toString("hex");\n}\n`,
  }[cat];
  const c = lang === 'python' || lang === 'ruby' ? '#' : '//';
  return `${c} Recommended fix for ${N}() in ${lang}:\n${c} ${ATTACKS[KIND_OF[cat]].fix}\n${c} (Reference code is only generated for Python and JavaScript.)\n`;
}

/* ------------------------------------------------------------------ predicted simulation */
function predict(b, patched) {
  const atk = ATTACKS[b.kind], name = b.fn.name, steps = [];
  const log = (kind, msg) => steps.push({kind, msg});
  log('info', 'Static mode: the code is analysed, not executed. Everything below is a prediction.');
  const out = (vulnerable, banner, leaked, response) => ({mode: MODE_PRED, vulnerable, banner, steps, users: USERS, leaked_ids: leaked, response});
  if (b.kind === 'sqli_sanitizer' || b.kind === 'sqli_validator') {
    log('attacker', 'Baseline request: GET /search?user=alice');
    log('attacker', 'Attack request: GET /search?user=' + atk.payload);
    if (!patched) {
      log('app', b.kind === 'sqli_sanitizer' ? `${name}(${JSON.stringify(atk.payload)}) -> predicted to pass the payload through. ${b.judge.reality}` : `${name}(...) -> predicted to return true for any input`);
      log('app', "Predicted SQL: SELECT id, username, email FROM users WHERE username = '" + atk.payload + "'");
      log('bad', 'The quote closes the string and OR 1=1 matches every row');
      return out(true, 'PREDICTED VULNERABLE: all 5 fake user records would be exposed (simulated, not executed)', USERS.map(u => u.id), 'Predicted: 5 leaked rows');
    }
    log('app', `${name}(...) with the reference patch -> predicted to strip or reject the quote`);
    log('app', "Predicted SQL: SELECT id, username, email FROM users WHERE username = ' OR 11'");
    log('ok', 'No rows leak');
    return out(false, 'PREDICTED BLOCKED with the reference patch (simulated, not executed)', [], 'Predicted: 0 leaked rows');
  }
  if (b.kind === 'fake_auth') {
    log('attacker', `Attack request: GET /admin with forged token '${atk.payload}'`);
    if (!patched) {
      log('app', `${name}('${atk.payload}') -> predicted true. ${b.judge.reality}`);
      log('bad', 'Forged token accepted, secret would be returned');
      return out(true, 'PREDICTED VULNERABLE: admin endpoint would open with a forged token (simulated, not executed)', [], 'Predicted: HTTP 200 with the secret');
    }
    log('app', `${name}('${atk.payload}') with the reference patch -> predicted false`);
    log('ok', 'Forged token rejected');
    return out(false, 'PREDICTED BLOCKED with the reference patch (simulated, not executed)', [], 'Predicted: HTTP 401');
  }
  log('attacker', `Hash '${atk.payload}' and compare against a rainbow table`);
  if (!patched) {
    log('app', `${name}('${atk.payload}') -> predicted fast, unsalted hash. ${b.judge.reality}`);
    log('bad', 'Precomputed tables crack this instantly');
    return out(true, 'PREDICTED VULNERABLE: password hash would match a rainbow table (simulated, not executed)', [], 'Predicted: table match');
  }
  log('app', `${name}('${atk.payload}') with the reference patch -> predicted salted PBKDF2 output`);
  log('ok', 'Salted, slow hash: lookup fails');
  return out(false, 'PREDICTED BLOCKED with the reference patch (simulated, not executed)', [], 'Predicted: no table match');
}

/* ------------------------------------------------------------------ session (same API shape as server.py) */
class ClientSession {
  constructor(opts) {
    opts = opts || {};
    this.sample = opts.sampleSource ? normalize(opts.sampleSource) : null;
    this.recorded = opts.recorded || null;
    this.src = null;
  }
  load(source, lang, label) {
    if (source.length > 200000) throw new Error('File is too large (limit 200 KB).');
    this.src = {source, lang, label};
    const funcs = extract(source, lang), claim = claiming(funcs);
    this.functionsFound = funcs.length;
    this.base = {};
    const counts = {}; claim.forEach(f => { counts[f.name] = (counts[f.name] || 0) + 1; });
    for (const f of claim) {
      const cat = category(f.name), id = counts[f.name] > 1 ? `${f.name}@${f.line}` : f.name;
      this.base[id] = {id, fn: f, judge: judge(f, lang), cat, kind: KIND_OF[cat], reach: reachability(funcs, f, lang)};
    }
    this.recordedActive = !!(this.recorded && this.sample && normalize(source) === this.sample);
    this.status = {}; this.exploit = {}; this.patches = {};
    const all = Object.values(this.base);
    this.trustBefore = all.length ? Math.round(1000 * all.filter(b => !b.judge.mismatch).length / all.length) / 10 : 100;
    return {functions: funcs.length, claiming: claim.length};
  }
  scan() {
    const all = Object.values(this.base), findings = [], honest = [];
    for (const b of all) {
      if (!b.judge.mismatch) { honest.push({name: b.fn.name, line: b.fn.line, claim: b.judge.claim, reality: b.judge.reality, lie_score: b.judge.lie_score}); continue; }
      const atk = ATTACKS[b.kind], cv = cvssFor(b.kind, b.reach.length > 0);
      const exploit = this.exploit[b.id] || 'not tested', status = this.status[b.id] || 'Open';
      const rec = this.recordedActive && this.recorded.fix_state[b.id];
      findings.push({
        id: b.id, file: this.src.label, function: b.fn.name, line: b.fn.line, claim: b.judge.claim, reality: b.judge.reality,
        mismatch: true, lie_score: b.judge.lie_score, current_lie_score: status === 'Verified' && rec ? rec.current_lie_score : null,
        reason: b.judge.reason, severity: cv.band, cvss_score: cv.score, cvss_vector: cv.vector, epss: null,
        owasp: atk.owasp, attack: atk.label, payload: atk.payload, reachable: b.reach.length > 0,
        evidence: b.reach.length ? b.reach : ['No request handler passes user input to this function.'],
        exploit, status, exploit_likelihood: likelihood(exploit, status), priority: priority(cv.band, exploit, status),
        mode: this.recordedActive ? MODE_REC : MODE_PRED, can_patch: this.recordedActive,
        recommended_fix: atk.fix, patch: this.patches[b.id] || null,
      });
    }
    findings.sort((a, b) => b.cvss_score - a.cvss_score || b.lie_score - a.lie_score);
    const verified = findings.filter(f => f.status === 'Verified').length;
    const honestN = all.filter(b => !b.judge.mismatch).length;
    return {
      target: this.src.label, findings, honest, users: USERS,
      counts: {Open: findings.filter(f => f.status === 'Open').length, Fixed: findings.filter(f => f.status === 'Fixed').length, Verified: verified},
      trust: {before: this.trustBefore, after: all.length ? Math.round(1000 * (honestN + verified) / all.length) / 10 : 100, honest: honestN, total: all.length},
      source_info: {label: this.src.label, language: this.src.lang, functions_found: this.functionsFound, claiming: all.length, mode: 'client'},
    };
  }
  simulate(id) {
    const b = this.base[id];
    if (!b || !b.judge.mismatch) return {error: 'unknown finding'};
    const patched = (this.status[id] || 'Open') !== 'Open';
    if (this.recordedActive) {
      if (patched) return JSON.parse(JSON.stringify(this.recorded.fix[id].result));
      this.exploit[id] = 'confirmed';
      return JSON.parse(JSON.stringify(this.recorded.simulate[id]));
    }
    if (!patched) this.exploit[id] = 'predicted (not executed)';
    return predict(b, patched);
  }
  applyFix(id) {
    const b = this.base[id];
    if (!b || !b.judge.mismatch) return {error: 'unknown finding'};
    if ((this.status[id] || 'Open') !== 'Open') return {error: 'Already patched.'};
    if (!this.exploit[id]) return {error: 'Run Simulate Attack first, so the fix answers a specific attack.'};
    if (this.recordedActive) {
      const rec = this.recorded.fix[id];
      this.status[id] = 'Verified'; this.patches[id] = rec.patch;
      return JSON.parse(JSON.stringify(rec));
    }
    const patch = referencePatch(this.src.lang, b.cat, b.fn);
    this.status[id] = 'Fixed'; this.patches[id] = patch;
    return {result: predict(b, true), status: 'Fixed', patch, needs_review: false, unverified: true};
  }
  reset() { if (this.src) this.load(this.src.source, this.src.lang, this.src.label); }
  handle(path, body) {
    if (path === '/api/scan') return this.scan();
    if (path === '/api/reset') { this.reset(); return {ok: true}; }
    if (path === '/api/simulate') return this.simulate(String((body || {}).id || ''));
    if (path === '/api/fix') return this.applyFix(String((body || {}).id || ''));
    return {error: 'not found'};
  }
}

const LD = {ClientSession, extract, claiming, judge, detectLang, cvss31, cvssFor, priority, reachability, referencePatch, normalize, KEYWORDS};
if (typeof module !== 'undefined' && module.exports) module.exports = LD; else root.LD = LD;
})(typeof window !== 'undefined' ? window : this);
