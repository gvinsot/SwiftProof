// SwiftProof website behaviour: platform detection, release data from GitHub,
// copy buttons, OS tabs and the reference filter. The pages stay usable
// without JavaScript: every download link falls back to GitHub Releases.
(function () {
  "use strict";

  var REPO = "gvinsot/SwiftProof";
  var RELEASES_PAGE = "https://github.com/" + REPO + "/releases";
  var API = "https://api.github.com/repos/" + REPO + "/releases?per_page=100";
  var CACHE_KEY = "swiftproof-releases-v1";
  var CACHE_MS = 10 * 60 * 1000;

  // Archive names are fixed by app/tools/build: swiftproof-<tag>-<os>-<arch>.<ext>.
  var PLATFORMS = [
    { id: "windows-amd64", os: "windows", label: "Windows", arch: "x64", ext: ".zip" },
    { id: "windows-arm64", os: "windows", label: "Windows", arch: "ARM64", ext: ".zip" },
    { id: "darwin-arm64", os: "darwin", label: "macOS", arch: "Apple silicon", ext: ".tar.gz" },
    { id: "darwin-amd64", os: "darwin", label: "macOS", arch: "Intel", ext: ".tar.gz" },
    { id: "linux-amd64", os: "linux", label: "Linux", arch: "x64", ext: ".tar.gz" },
    { id: "linux-arm64", os: "linux", label: "Linux", arch: "ARM64", ext: ".tar.gz" }
  ];

  // Used only when the GitHub API is unreachable or rate limited. Download
  // URLs are derived from the naming convention, so older entries stay valid;
  // newer releases appear automatically once the API answers again.
  var FALLBACK = [
    { tag: "v0.3.0", date: "2026-09-20T21:53:03Z" },
    { tag: "v0.2.0", date: "2026-09-20T10:06:27Z" },
    { tag: "v0.1.0", date: "2026-09-19T21:32:40Z" }
  ];

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function platform(id) { for (var i = 0; i < PLATFORMS.length; i++) if (PLATFORMS[i].id === id) return PLATFORMS[i]; return PLATFORMS[0]; }
  function archiveName(tag, p) { return "swiftproof-" + tag + "-" + p.id + p.ext; }
  function assetUrl(tag, p) { return RELEASES_PAGE + "/download/" + tag + "/" + archiveName(tag, p); }
  function escapeHtml(s) { return String(s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
  function formatDate(iso) {
    var d = new Date(iso);
    return isNaN(d) ? "" : d.toLocaleDateString("en", { year: "numeric", month: "long", day: "numeric" });
  }
  function formatSize(bytes) { return bytes ? (bytes / 1048576).toFixed(1) + " MB" : ""; }
  function storage(action, value) {
    try {
      if (action === "get") return JSON.parse(sessionStorage.getItem(CACHE_KEY) || "null");
      sessionStorage.setItem(CACHE_KEY, JSON.stringify(value));
    } catch (e) { /* private mode or blocked storage: no cache */ }
    return null;
  }

  // ---------------------------------------------------------------- platform

  function detectPlatform() {
    var ua = navigator.userAgent || "";
    var hint = navigator.userAgentData;
    var os = /Windows/i.test(ua) ? "windows"
      : /Macintosh|Mac OS X|iPhone|iPad/i.test(ua) ? "darwin"
      : /Linux|X11|CrOS|Android/i.test(ua) ? "linux" : "windows";
    var mobile = /Android|iPhone|iPad|Mobile/i.test(ua) || (hint && hint.mobile);
    // Safari reports Intel on every Mac; new Macs are Apple silicon.
    var arch = os === "darwin" ? "arm64" : /aarch64|arm64|armv8/i.test(ua) ? "arm64" : "amd64";
    var guess = { id: os + "-" + arch, mobile: !!mobile, exact: os !== "darwin" };
    if (!hint || !hint.getHighEntropyValues) return Promise.resolve(guess);
    return hint.getHighEntropyValues(["architecture", "bitness"]).then(function (v) {
      if (v.architecture === "arm" && v.bitness === "64") arch = "arm64";
      else if (v.architecture === "x86") arch = "amd64";
      return { id: os + "-" + arch, mobile: !!mobile, exact: true };
    }, function () { return guess; });
  }

  // ---------------------------------------------------------------- releases

  function normalize(list) {
    return list.filter(function (r) { return !r.draft; }).map(function (r) {
      var assets = {};
      (r.assets || []).forEach(function (a) { assets[a.name] = { url: a.browser_download_url, size: a.size }; });
      return { tag: r.tag_name, date: r.published_at, prerelease: !!r.prerelease, notes: r.body || "", url: r.html_url, assets: assets };
    });
  }

  function fallback() {
    return FALLBACK.map(function (r) {
      return { tag: r.tag, date: r.date, prerelease: false, notes: "", url: RELEASES_PAGE + "/tag/" + r.tag, assets: {}, offline: true };
    });
  }

  var releasesPromise;
  function loadReleases() {
    if (releasesPromise) return releasesPromise;
    var cached = storage("get");
    if (cached && Date.now() - cached.time < CACHE_MS && cached.releases.length) {
      releasesPromise = Promise.resolve(cached.releases);
      return releasesPromise;
    }
    releasesPromise = fetch(API, { headers: { Accept: "application/vnd.github+json" } })
      .then(function (res) { if (!res.ok) throw new Error("GitHub API " + res.status); return res.json(); })
      .then(function (json) {
        var releases = normalize(json);
        if (!releases.length) throw new Error("no releases");
        storage("set", { time: Date.now(), releases: releases });
        return releases;
      })
      .catch(function () { return fallback(); });
    return releasesPromise;
  }

  function latestStable(releases) {
    for (var i = 0; i < releases.length; i++) if (!releases[i].prerelease) return releases[i];
    return releases[0];
  }

  function link(release, p) {
    var a = release.assets[archiveName(release.tag, p)];
    return { url: a ? a.url : assetUrl(release.tag, p), size: a ? a.size : 0 };
  }

  // A deliberately small Markdown subset for release notes: headings, lists,
  // paragraphs, inline code, bold and links. Input is escaped first.
  function markdown(src, base) {
    var html = [], para = [], list = false;
    function inline(s) {
      return escapeHtml(s)
        .replace(/`([^`]+)`/g, "<code>$1</code>")
        .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
        .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, function (_, text, href) {
          var url;
          try { url = new URL(href.replace(/&amp;/g, "&"), base).href; } catch (e) { return text; }
          if (!/^https?:/.test(url)) return text;
          return '<a href="' + escapeHtml(url) + '" rel="noopener">' + text + "</a>";
        });
    }
    function flush() {
      if (para.length) { html.push("<p>" + inline(para.join(" ")) + "</p>"); para = []; }
    }
    function closeList() { if (list) { html.push("</ul>"); list = false; } }
    src.replace(/\r/g, "").split("\n").forEach(function (line) {
      var h = /^(#{1,4})\s+(.*)$/.exec(line), li = /^\s*[-*]\s+(.*)$/.exec(line);
      if (h) { flush(); closeList(); if (h[1].length > 1) html.push("<h3>" + inline(h[2]) + "</h3>"); }
      else if (li) { flush(); if (!list) { html.push("<ul>"); list = true; } html.push("<li>" + inline(li[1]) + "</li>"); }
      else if (!line.trim()) { flush(); closeList(); }
      else if (list && /^\s+/.test(line)) { html[html.length - 1] = html[html.length - 1].replace(/<\/li>$/, " " + inline(line.trim()) + "</li>"); }
      else { closeList(); para.push(line.trim()); }
    });
    flush(); closeList();
    return html.join("\n");
  }

  // ------------------------------------------------------------- page wiring

  function fillVersionPlaceholders(release) {
    $$("[data-version]").forEach(function (el) { el.textContent = release.tag; });
  }

  function wireDownloadButtons(release, detected) {
    var p = platform(detected.id);
    $$("[data-download-latest]").forEach(function (a) {
      a.href = link(release, p).url;
      a.textContent = "Download for " + p.label + (detected.exact || p.os !== "darwin" ? " " + p.arch : "");
      a.setAttribute("download", "");
    });
    $$("[data-download-href]").forEach(function (a) { a.href = link(release, p).url; });
  }

  function renderDownloadPage(releases, detected) {
    var hero = $("#dl-hero");
    if (!hero) return;
    var latest = latestStable(releases);
    var p = platform(detected.id);
    var main = link(latest, p);
    var offline = latest.offline;

    $("#dl-version").textContent = "SwiftProof " + latest.tag;
    $("#dl-meta").innerHTML = "Released " + escapeHtml(formatDate(latest.date)) +
      ' · <a href="' + escapeHtml(latest.url) + '">release notes</a>' +
      ' · <a href="' + escapeHtml(RELEASES_PAGE + "/download/" + latest.tag + "/SHA256SUMS") + '">SHA256SUMS</a>';
    var btn = $("#dl-main");
    btn.href = main.url;
    btn.textContent = "Download for " + p.label + " " + p.arch;
    $("#dl-file").textContent = archiveName(latest.tag, p) + (main.size ? " · " + formatSize(main.size) : "");
    var note = $("#dl-detect");
    if (detected.mobile) note.textContent = "SwiftProof is a command-line tool for desktop and server systems. Pick the platform of the machine you will run it on.";
    else if (!detected.exact) note.textContent = "Detected " + p.label + ". On an Intel Mac, choose macOS Intel below.";
    else note.textContent = "Detected from your browser: " + p.label + " " + p.arch + ". Other platforms are listed alongside.";

    $("#dl-platforms").innerHTML = PLATFORMS.map(function (q) {
      var l = link(latest, q);
      return '<a href="' + escapeHtml(l.url) + '"' + (q.id === p.id ? ' class="current" aria-current="true"' : "") + ">" +
        "<span>" + q.label + " " + q.arch + "</span><small>" + q.ext + (l.size ? " · " + formatSize(l.size) : "") + "</small></a>";
    }).join("");

    var status = $("#releases-status");
    status.textContent = offline
      ? "GitHub could not be reached, so this list may be incomplete and has no notes. The complete history is on GitHub Releases."
      : releases.length + " releases, newest first.";

    $("#releases").innerHTML = releases.map(function (r, i) {
      var rows = PLATFORMS.map(function (q) {
        var l = link(r, q);
        return "<tr" + (q.id === p.id ? ' class="mine"' : "") + "><td>" + q.label + " " + q.arch + (q.id === p.id ? ' <span class="badge">yours</span>' : "") + "</td>" +
          '<td><a href="' + escapeHtml(l.url) + '"><code>' + escapeHtml(archiveName(r.tag, q)) + "</code></a></td>" +
          "<td>" + (l.size ? formatSize(l.size) : "—") + "</td></tr>";
      }).join("");
      var notesBase = "https://github.com/" + REPO + "/blob/main/app/docs/releases/";
      return '<details class="release"' + (i === 0 ? " open" : "") + ' id="' + escapeHtml(r.tag) + '">' +
        "<summary><h3>" + escapeHtml(r.tag) + "</h3><time datetime=\"" + escapeHtml(r.date) + "\">" + escapeHtml(formatDate(r.date)) + "</time>" +
        (r === latest ? '<span class="badge">latest</span>' : "") + (r.prerelease ? '<span class="badge pre">pre-release</span>' : "") + "</summary>" +
        '<div class="release-body">' +
        '<div class="table-wrap"><table><thead><tr><th>Platform</th><th>Archive</th><th>Size</th></tr></thead><tbody>' + rows +
        '<tr><td>Checksums</td><td><a href="' + escapeHtml(RELEASES_PAGE + "/download/" + r.tag + "/SHA256SUMS") + '"><code>SHA256SUMS</code></a></td><td>—</td></tr>' +
        "</tbody></table></div>" +
        (r.notes ? '<div class="release-notes">' + markdown(r.notes, notesBase) + "</div>" : '<p class="status"><a href="' + escapeHtml(r.url) + '">Read the release notes on GitHub</a>.</p>') +
        "</div></details>";
    }).join("");

    if (location.hash) {
      var target = document.getElementById(decodeURIComponent(location.hash.slice(1)));
      if (target && target.tagName === "DETAILS") { target.open = true; target.scrollIntoView(); }
    }
  }

  // ------------------------------------------------------- tabs, copy, docs

  function wireTabs(detected) {
    var os = platform(detected.id).os;
    $$("[data-tabs]").forEach(function (group) {
      var buttons = $$('[role="tab"]', group);
      function select(btn) {
        buttons.forEach(function (b) {
          var on = b === btn;
          b.setAttribute("aria-selected", on ? "true" : "false");
          b.tabIndex = on ? 0 : -1;
          document.getElementById(b.getAttribute("aria-controls")).hidden = !on;
        });
      }
      buttons.forEach(function (b, i) {
        b.addEventListener("click", function () { select(b); });
        b.addEventListener("keydown", function (e) {
          var d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
          if (d) { var n = buttons[(i + d + buttons.length) % buttons.length]; select(n); n.focus(); }
        });
      });
      var preferred = buttons.filter(function (b) { return (b.getAttribute("data-os") || "").split(" ").indexOf(os) >= 0; })[0];
      select(preferred || buttons[0]);
    });
  }

  function wireCopyButtons() {
    $$(".code pre").forEach(function (pre) {
      var button = document.createElement("button");
      button.type = "button";
      button.className = "copy";
      button.textContent = "Copy";
      button.addEventListener("click", function () {
        var clone = pre.cloneNode(true);
        $$(".p, .o", clone).forEach(function (el) { el.remove(); });
        var text = clone.textContent.replace(/\n{2,}/g, "\n").trim();
        var done = function () {
          button.textContent = "Copied";
          button.classList.add("done");
          setTimeout(function () { button.textContent = "Copy"; button.classList.remove("done"); }, 1600);
        };
        if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, function () {});
      });
      pre.parentNode.appendChild(button);
    });
  }

  function wireReference() {
    var input = $("#ref-filter");
    if (!input) return;
    var sections = $$(".ref-main > section");
    var navLinks = $$(".ref-side a[href^='#']");
    var count = $("#ref-count");
    var rows = $$(".ref-main tbody tr");
    rows.forEach(function (tr) { tr.setAttribute("data-text", tr.textContent.toLowerCase()); });

    function unmark(root) {
      $$("mark", root).forEach(function (m) { m.replaceWith(document.createTextNode(m.textContent)); });
      root.normalize();
    }
    function mark(root, term) {
      var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      var nodes = [], n;
      while ((n = walker.nextNode())) nodes.push(n);
      nodes.forEach(function (node) {
        var i = node.nodeValue.toLowerCase().indexOf(term);
        if (i < 0) return;
        var hit = node.splitText(i);
        hit.splitText(term.length);
        var m = document.createElement("mark");
        m.textContent = hit.nodeValue;
        hit.replaceWith(m);
      });
    }

    function apply() {
      var term = input.value.trim().toLowerCase();
      var matches = 0;
      sections.forEach(function (section) {
        unmark(section);
        var sectionRows = $$("tbody tr", section);
        var textHit = !term || section.textContent.toLowerCase().indexOf(term) >= 0;
        var rowHits = 0;
        sectionRows.forEach(function (tr) {
          var hit = !term || tr.getAttribute("data-text").indexOf(term) >= 0;
          tr.hidden = !hit;
          if (hit) rowHits++;
        });
        // A section is kept when a table row or its prose matches; rows that
        // do not match are hidden so the matching options stand out.
        var keep = !term || rowHits > 0 || textHit;
        if (term && rowHits === 0 && textHit) sectionRows.forEach(function (tr) { tr.hidden = false; });
        section.hidden = !keep;
        if (keep && term) { matches += rowHits || 1; mark(section, term); }
        var navLink = $(".ref-side a[href='#" + section.id + "']");
        if (navLink) navLink.parentNode.hidden = !keep;
      });
      count.textContent = term ? (matches ? matches + " match" + (matches > 1 ? "es" : "") : "No match. Try a flag such as --base or a key such as memory_mb.") : "";
      try { history.replaceState(null, "", term ? "?q=" + encodeURIComponent(term) + location.hash : location.pathname + location.hash); } catch (e) { /* file:// */ }
    }
    input.addEventListener("input", apply);
    document.addEventListener("keydown", function (e) {
      if (e.key === "/" && document.activeElement !== input && !/INPUT|TEXTAREA/.test(document.activeElement.tagName)) { e.preventDefault(); input.focus(); }
      if (e.key === "Escape" && document.activeElement === input) { input.value = ""; apply(); }
    });
    var q = new URLSearchParams(location.search).get("q");
    if (q) { input.value = q; apply(); }

    if ("IntersectionObserver" in window) {
      var observer = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          navLinks.forEach(function (a) { a.classList.toggle("active", a.getAttribute("href") === "#" + entry.target.id); });
        });
      }, { rootMargin: "-80px 0px -70% 0px" });
      sections.forEach(function (s) { observer.observe(s); });
    }
  }

  // ------------------------------------------------------------------- start

  wireCopyButtons();
  wireReference();
  detectPlatform().then(function (detected) {
    wireTabs(detected);
    var needsReleases = $("[data-download-latest], [data-download-href], [data-version], #dl-hero");
    if (!needsReleases) return;
    loadReleases().then(function (releases) {
      var latest = latestStable(releases);
      fillVersionPlaceholders(latest);
      wireDownloadButtons(latest, detected);
      renderDownloadPage(releases, detected);
    });
  });
})();
