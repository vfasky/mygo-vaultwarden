// Node oracle: official npm zxcvbn 4.4.2, no application Go code.
// Usage: node generate-vectors.cjs /absolute/path/to/zxcvbn.js > vectors.json
// Freeze the oracle year: zxcvbn date guesses intentionally depend on the year.
const RealDate = Date;
global.Date = class extends RealDate {
 constructor(...args) { super(...(args.length ? args : ['2026-01-01T00:00:00Z'])); }
 static now() { return new RealDate('2026-01-01T00:00:00Z').getTime(); }
};
const zxcvbn = require(process.argv[2]);
const cases = [
 ['empty', '', '', []],
 ['common', 'password', '', []],
 ['mixed-common', 'P@ssw0rd!', '', []],
 ['keyboard', 'qwertyuiop', '', []],
 ['repeated', 'abcabcabcabc', '', []],
 ['sequence', 'abcdefghi', '', []],
 ['date', '1991-12-25', '', []],
 ['long-sequence', 'abcdefghijk', '', []],
 ['keyboard-plus-words', 'zxcvbn2024!cat', '', []],
 ['leet-example', 'Tr0ub4dor&3', '', []],
 ['passphrase', 'correct horse battery staple', '', []],
 ['strong', 'u5V!m8#Q2p@L7r$N', '', []],
 ['brand', 'bitwarden123', '', []],
 ['email-parts', 'snowflake2025!', ' SnowFlake.Manager+Dev@example.invalid', []],
 ['email-domain-excluded', 'snowflake2025!', 'different@snowflake.invalid', []],
 ['email-no-at', 'snowflake2025!', 'snowflake', []],
 ['empty-email-tokens', 'example', '.+@example.invalid', []],
 ['user-dictionary', 'quasar12345', '', ['quasar','quasar','bitwarden']],
 ['uppercase-user-input', 'QuAsAr12345', '', ['QUASAR']],
 ['cjk', '密码保险库测试中文短语', '', []],
 ['emoji', '🔐🔑🦉🌙✨', '', []],
 ['unicode-user', 'İstanbul2025!', 'İSTANBUL@example.invalid', []],
 ['unicode-trim', 'snowflake2025!', '\uFEFFSnowFlake\u00A0@example.invalid', []],
 ['decomposed', 'cafe\u0301cafe\u0301', '', []],
 ['composed', 'cafécafé', '', []],
 ['astral-repeat', '🔐🔐🔐🔐', '', []],
 ['nul', 'abc\u0000def123!', '', []],
 ['whitespace', '  lead and trail  ', '', []],
];
function official(password,email,userInputs) {
 if (password == null || password.length === 0) return null;
 const at = email.indexOf('@');
 const tokens = email == null || email.length === 0 || at < 0 ? [] : email.substring(0,at).trim().toLowerCase().split(/[^A-Za-z0-9]/);
 const inputs = Array.from(new Set(['bitwarden','bit','warden',...(userInputs??[]),...tokens]));
 const r=zxcvbn(password,inputs);
 return {score:r.score, guessesLog10:r.guesses_log10};
}
console.log(JSON.stringify(cases.map(([name,password,email,userInputs])=>({name,password,email,userInputs,expected:official(password,email,userInputs)})),null,2));
