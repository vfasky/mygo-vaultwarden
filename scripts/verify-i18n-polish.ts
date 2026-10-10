// SPDX-License-Identifier: GPL-3.0-only
// Run with Bun: bun scripts/verify-i18n-polish.ts [baseline-ref]
// Compare every Go string literal that names a catalog key, including T/Tf
// calls, switch results, tables, and tests. Also reject non-i18n token changes.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const baseline = process.argv[2] ?? "bf8a097";
const git = (...args: string[]) => execFileSync("git", args, { encoding: "utf8" });
const paths = git("ls-tree", "-r", "--name-only", baseline).trim().split("\n").filter(p => p.endsWith(".go"));
const catalogPaths = paths.filter(p => p.startsWith("internal/i18n/") && !/(?:i18n|catalog_test|locale_\w+)\.go$/.test(p));
type Message = { zh: string; en: string };
function catalog(read: (path: string) => string) {
  const result = new Map<string, Message>();
  for (const path of catalogPaths) {
    for (const match of read(path).matchAll(/^\s*"([a-z][a-z0-9_.]+)":\s*\{("(?:[^"\\]|\\.)*"),\s*("(?:[^"\\]|\\.)*")\},$/gm)) {
      if (result.has(match[1])) throw new Error(`Duplicate key: ${match[1]}`);
      result.set(match[1], { zh: JSON.parse(match[2]), en: JSON.parse(match[3]) });
    }
  }
  return result;
}
const originals = new Map(paths.map(path => [path, git("show", `${baseline}:${path}`)]));
const before = catalog(path => originals.get(path)!);
const after = catalog(path => readFileSync(path, "utf8"));
// Consume comments and quoted/raw strings as whole tokens before identifiers
// and punctuation, so formatting changes cannot hide a changed literal.
function tokens(source: string) {
  return [...source.matchAll(/\/\/[^\n]*|\/\*[\s\S]*?\*\/|"(?:[^"\\]|\\.)*"|`[^`]*`|'(?:[^'\\]|\\.)*'|[\p{L}\p{N}_]+|[^\s]/gu)]
    .map(match => match[0]).filter(token => !token.startsWith("//") && !token.startsWith("/*"));
}
function message(token: string, messages: Map<string, Message>) {
  if (!/^"[a-z][a-z0-9_.]+"$/.test(token)) return undefined;
  return messages.get(token.slice(1, -1));
}
let keyReferences = 0;
let literalCalls = 0;
let changedReferences = 0;
let checkedFiles = 0;
const englishChanges = new Map<string, string>();
for (const path of paths) {
  if (catalogPaths.includes(path)) continue;
  const oldTokens = tokens(originals.get(path)!);
  const newTokens = tokens(readFileSync(path, "utf8"));
  if (oldTokens.length !== newTokens.length) throw new Error(`${path}: token count changed`);
  for (let i = 0; i < oldTokens.length; i++) {
    const oldMessage = message(oldTokens[i], before);
    const newMessage = message(newTokens[i], after);
    if (oldMessage || newMessage) {
      if (!oldMessage || !newMessage || oldMessage.zh !== newMessage.zh) throw new Error(`${path}: Chinese changed at token ${i}: ${oldTokens[i]} → ${newTokens[i]}`);
      if (oldMessage.en.toLowerCase() !== newMessage.en.toLowerCase()) throw new Error(`${path}: English meaning changed: ${oldTokens[i]}`);
      keyReferences++;
      if (oldTokens[i] !== newTokens[i]) changedReferences++;
      if (oldTokens[i - 1] === "(" && /^(T|Tf)$/.test(oldTokens[i - 2])) literalCalls++;
      if (oldMessage.en !== newMessage.en) englishChanges.set(oldMessage.en, newMessage.en);
    } else if (oldTokens[i] !== newTokens[i]) {
      // English test expectations may change only by case, matching a catalog change.
      const oldText = oldTokens[i].startsWith('"') ? oldTokens[i].slice(1, -1) : "";
      const newText = newTokens[i].startsWith('"') ? newTokens[i].slice(1, -1) : "";
      const allowed = path.endsWith("_test.go") && oldText && oldText.toLowerCase() === newText.toLowerCase()
        && [...before.values()].some(m => m.en === oldText) && [...after.values()].some(m => m.en === newText);
      if (!allowed) throw new Error(`${path}: non-i18n token changed at ${i}: ${oldTokens[i]} → ${newTokens[i]}`);
    }
  }
  checkedFiles++;
}
for (const [key, entry] of after) {
  if (![...before.values()].some(old => old.zh === entry.zh && old.en.toLowerCase() === entry.en.toLowerCase())) throw new Error(`New or changed translation: ${key}`);
}
console.log(JSON.stringify({ baseline, before: before.size, after: after.size, checkedFiles, keyReferences, literalCalls, changedReferences, chineseDifferences: 0, nonI18nTokenDifferences: 0, englishCaseChanges: englishChanges.size }, null, 2));
