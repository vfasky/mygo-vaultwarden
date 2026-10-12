// 从 GitHub Releases 生成 public/data/releases.json（构建时静态化，访问时不依赖 GitHub API）。
import { writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const repo = process.env.GITHUB_REPO || "vfasky/mygo-vaultwarden";
const headers = { Accept: "application/vnd.github+json", "User-Agent": "mygo-vaultwarden-web" };
if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

const res = await fetch(`https://api.github.com/repos/${repo}/releases?per_page=100`, { headers });
if (!res.ok) throw new Error(`GitHub API ${res.status}: ${await res.text()}`);

// Release 说明来自 CHANGELOG.md，按 “### 中文” 与 “### English” 分段；
// 没有分段标题的旧说明整体视为中文。
function notesOf(body) {
  const notes = { zh: [], en: [] };
  let lang = "zh";
  for (const raw of (body || "").replace(/\r\n/g, "\n").split("\n")) {
    const line = raw.trim();
    const heading = line.match(/^#{2,4}\s+(.+)$/);
    if (heading) {
      if (/^(english|en)$/i.test(heading[1].trim())) lang = "en";
      else if (/^(中文|简体中文|chinese|zh)$/i.test(heading[1].trim())) lang = "zh";
      continue;
    }
    if (/^[-*]\s+/.test(line)) notes[lang].push(line.replace(/^[-*]\s+/, ""));
  }
  return notes;
}

// 低于此版本的 release 不在网站展示（0.1.2 及更早版本为通用安装包，不再提供）
const MIN_VERSION = "0.1.3";
const cmp = (a, b) => {
  const [x, y] = [a, b].map((v) => v.split(".").map(Number));
  for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
  return 0;
};

const releases = [];
for (const r of await res.json()) {
  if (r.draft || r.prerelease) continue;
  const version = r.tag_name.replace(/^v/, "");
  if (cmp(version, MIN_VERSION) < 0) continue;
  const find = (re) => r.assets.find((a) => re.test(a.name))?.browser_download_url ?? null;
  const { zh, en } = notesOf(r.body);
  if (!en.length) console.warn(`警告：${r.tag_name} 的 release 说明没有 “### English” 段落，英文页面将显示中文。`);
  releases.push({
    version,
    tag: r.tag_name,
    date: r.published_at,
    url: r.html_url,
    notes: { zh, en: en.length ? en : zh },
    downloads: {
      appleSilicon: find(/AppleSilicon\.dmg$/),
      intel: find(/Intel\.dmg$/),
      universal: find(/macOS\.(dmg|zip)$/),
      checksums: find(/^SHA256SUMS\.txt$/),
    },
  });
}
releases.sort((a, b) => new Date(b.date) - new Date(a.date));
if (!releases.length) throw new Error("没有找到已发布的 release");

await mkdir(join(root, "public/data"), { recursive: true });
await writeFile(
  join(root, "public/data/releases.json"),
  JSON.stringify({ repo, generatedAt: new Date().toISOString(), releases }, null, 2) + "\n",
);
console.log(`已写入 ${releases.length} 个版本，最新 ${releases[0].version}`);
