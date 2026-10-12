(() => {
  const root = document.documentElement;
  const titles = {
    zh: "MyGo Vaultwarden — 为 macOS 打造的原生 Vaultwarden 客户端",
    en: "MyGo Vaultwarden — A native macOS client for Vaultwarden",
  };

  const saved = (() => { try { return localStorage.getItem("lang"); } catch { return null; } })();
  const initial = saved || (/^zh/i.test(navigator.language || "") ? "zh" : "en");

  function setLang(lang) {
    root.dataset.lang = lang;
    root.lang = lang === "zh" ? "zh-CN" : "en";
    document.title = titles[lang];
    try { localStorage.setItem("lang", lang); } catch {}
    renderDates();
  }

  document.getElementById("lang").addEventListener("click", () => {
    setLang(root.dataset.lang === "zh" ? "en" : "zh");
  });

  const fmt = (iso, lang) =>
    new Date(iso).toLocaleDateString(lang === "zh" ? "zh-CN" : "en-US", { year: "numeric", month: "long", day: "numeric" });

  function renderDates() {
    document.querySelectorAll("[data-date]").forEach((el) => {
      el.textContent = fmt(el.dataset.date, el.dataset.dl);
    });
  }

  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };
  const bi = (zh, en) => {
    const frag = document.createDocumentFragment();
    const a = el("span", null, zh); a.dataset.l = "zh";
    const b = el("span", null, en); b.dataset.l = "en";
    frag.append(a, b);
    return frag;
  };

  function renderLog(releases) {
    const log = document.getElementById("log");
    log.replaceChildren();
    releases.forEach((r, i) => {
      const card = el("article", "entry" + (i >= 5 ? " extra" : ""));
      const head = el("header");
      head.append(el("h3", null, "v" + r.version));
      const dates = document.createDocumentFragment();
      for (const lang of ["zh", "en"]) {
        const t = el("time"); t.dataset.l = lang; t.dataset.dl = lang; t.dataset.date = r.date;
        dates.append(t);
      }
      head.append(dates);
      card.append(head);

      for (const lang of ["zh", "en"]) {
        const ul = el("ul"); ul.dataset.l = lang;
        (r.notes[lang] || []).forEach((t) => ul.append(el("li", null, t)));
        card.append(ul);
      }

      const foot = el("footer");
      const d = r.downloads;
      const add = (url, zh, en) => {
        if (!url) return;
        const a = el("a", "dl-link"); a.href = url; a.append(bi(zh, en)); foot.append(a);
      };
      add(d.appleSilicon, "Apple 芯片 DMG", "Apple silicon DMG");
      add(d.intel, "Intel DMG", "Intel DMG");
      add(d.universal, "安装包", "Installer");
      const gh = el("a", "dl-link quiet"); gh.href = r.url; gh.rel = "noopener"; gh.textContent = "GitHub";
      foot.append(gh);
      card.append(foot);
      log.append(card);
    });
    renderDates();

    const more = document.getElementById("more");
    if (releases.length > 5) {
      more.hidden = false;
      more.addEventListener("click", () => {
        log.classList.add("all");
        more.hidden = true;
      });
    }
  }

  function applyLatest(r) {
    document.querySelectorAll("[data-version]").forEach((n) => (n.textContent = "v" + r.version));
    const d = r.downloads;
    document.querySelectorAll("[data-dl]").forEach((a) => {
      const url = d[a.dataset.dl];
      if (url) a.href = url;
    });
  }

  setLang(initial);
  fetch("/data/releases.json")
    .then((res) => res.json())
    .then((data) => {
      applyLatest(data.releases[0]);
      renderLog(data.releases);
    })
    .catch(() => {
      document.getElementById("log").replaceChildren(el("p", "sub", "GitHub Releases"));
    });
})();
