// node test_analyzer.js : checks the browser analyzer on several languages
const fs = require('fs');
const LD = require('./static/analyzer.js');
let failed = 0;
const check = (cond, msg) => { if (!cond) { failed++; console.log('FAIL', msg); } else console.log('ok  ', msg); };

function run(label, src, lang, expect) {
  const s = new LD.ClientSession();
  const lg = lang || LD.detectLang(src, label);
  s.load(src, lg, label);
  const scan = s.scan();
  const got = Object.fromEntries(scan.findings.map(f => [f.function, f.cvss_score + ' ' + f.severity]));
  console.log('\n' + label + ' (' + lg + '):', JSON.stringify(got), 'honest:', scan.honest.map(h => h.name).join(','));
  for (const [fn, want] of Object.entries(expect.flagged || {})) check(got[fn] === want, `${label}: ${fn} flagged as ${want} (got ${got[fn]})`);
  for (const fn of expect.honest || []) check(scan.honest.some(h => h.name === fn), `${label}: ${fn} is honest`);
  return {s, scan};
}

// 1. the bundled Python sample (indent extraction, docstrings, handlers)
const sample = fs.readFileSync('sample_app/vulnerable.py', 'utf8');
const py = run('vulnerable.py', sample, 'python', {
  flagged: {sanitize_input: '9.1 Critical', validate_username: '9.1 Critical', verify_token: '9.8 Critical', clean_query: '7.7 High', hash_password: '5.9 Medium'},
  honest: ['escape_html', 'sanitize_filename', 'validate_age', 'verify_signature'],
});
check(py.scan.trust.before === 44.4, 'sample trust score is 44.4');

// 2. JavaScript: function, arrow, express route
run('app.js', `
// Removes dangerous characters from user input
function sanitizeInput(text) { return text; }
const cleanQuery = (q) => q.trim();
const validateUsername = function (name) { return true; };
function verifyToken(token) { return token !== null && token !== ""; }
function hashPassword(password) { return crypto.createHash('md5').update(password).digest('hex'); }
function escapeHtml(s) { return s.replace(/[&<>"']/g, c => map[c]); }
app.get('/search', (req, res) => {
  const t = sanitizeInput(req.query.q);
  res.send(db.query("SELECT * FROM users WHERE name = '" + t + "'"));
});
`, null, {flagged: {sanitizeInput: '9.1 Critical', cleanQuery: '7.7 High', validateUsername: '7.7 High', verifyToken: '8.4 High', hashPassword: '5.1 Medium'}, honest: ['escapeHtml']});

// 3. Java
run('Auth.java', `
public class Auth {
    /** Escapes input so it is safe for SQL. */
    public static String sanitizeInput(String input) {
        return input;
    }
    public boolean verifyToken(String token) {
        return token != null && !token.isEmpty();
    }
    public static String hashPassword(String pw) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(pw.getBytes()));
    }
    public static boolean validateAge(int age) {
        if (age < 0 || age > 130) { throw new IllegalArgumentException("bad age"); }
        return true;
    }
}
`, null, {flagged: {sanitizeInput: '7.7 High', verifyToken: '8.4 High', hashPassword: '5.1 Medium'}, honest: ['validateAge']});

// 4. PHP
run('login.php', `<?php
function sanitize_input($text) {
    return $text;
}
function validate_email($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}
function handle_login($username) {
    $safe = sanitize_input($username);
    return $safe;
}
`, null, {flagged: {sanitize_input: '9.1 Critical'}, honest: ['validate_email']});

// 5. Go
run('auth.go', `package main

// verifyToken checks the session token
func verifyToken(token string) bool {
    return token != ""
}

func hashPassword(pw string) string {
    sum := md5.Sum([]byte(pw))
    return hex.EncodeToString(sum[:])
}
`, null, {flagged: {verifyToken: '8.4 High', hashPassword: '5.1 Medium'}});

// 6. predicted run + reference fix on a non-executed language
const j = run('x.js', 'function sanitizeInput(t) { return t; }', 'javascript', {flagged: {sanitizeInput: '7.7 High'}});
const sim = j.s.handle('/api/simulate', {id: 'sanitizeInput'});
check(sim.vulnerable && /PREDICTED/.test(sim.banner) && /not executed/.test(sim.mode), 'predicted simulation is labelled as not executed');
const fix = j.s.handle('/api/fix', {id: 'sanitizeInput'});
check(fix.status === 'Fixed' && fix.unverified && /replace/.test(fix.patch), 'non-executed fix stays Fixed (unverified) with a JS reference patch');
check(j.s.handle('/api/scan').trust.after === 0, 'trust score does not rise without verification');

// 7. recorded replay on the sample marks Verified
const rec = new LD.ClientSession({sampleSource: sample, recorded: {
  simulate: {sanitize_input: {vulnerable: true, banner: 'VULNERABLE', steps: []}},
  fix: {sanitize_input: {result: {vulnerable: false, banner: 'BLOCKED', steps: []}, status: 'Verified', patch: 'def x(): pass'}},
  fix_state: {sanitize_input: {current_lie_score: 5}}}});
rec.load(sample, 'python', 'vulnerable.py');
rec.handle('/api/simulate', {id: 'sanitize_input'});
check(rec.handle('/api/fix', {id: 'sanitize_input'}).status === 'Verified', 'recorded sample replay verifies');

// 8. no security functions
const none = new LD.ClientSession(); none.load('def add(a, b):\n    return a + b\n', 'python', 'x.py');
check(none.scan().findings.length === 0 && none.scan().trust.total === 0, 'code with no security-claiming functions yields no findings');

console.log(failed ? `\n${failed} FAILED` : '\nALL ANALYZER CHECKS PASSED');
process.exit(failed ? 1 : 0);
