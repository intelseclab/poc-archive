(function () {
  "use strict";

  var root = document.getElementById("poc-explorer");
  if (!root) return;

  var fixedCategory = root.getAttribute("data-fixed-category") || "";
  var indexURL = root.getAttribute("data-search-index");

  var rowsEl = document.getElementById("poc-rows");
  var rows = Array.prototype.slice.call(rowsEl.querySelectorAll(".poc-row"));
  var countEl = document.getElementById("poc-count");
  var emptyEl = document.getElementById("poc-empty");
  var searchEl = document.getElementById("poc-search");
  var fromEl = document.getElementById("filter-from");
  var toEl = document.getElementById("filter-to");
  var clearEl = document.getElementById("filter-clear");

  var ACTIVE = ["border-emerald-400", "bg-emerald-400/10", "text-emerald-600", "dark:text-emerald-400"];
  var SEV_ORDER = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 };
  var SEV_COLORS = {
    Critical: "border-red-400/40 text-red-600 dark:text-red-400",
    High:     "border-orange-400/40 text-orange-600 dark:text-orange-400",
    Medium:   "border-yellow-400/40 text-yellow-600 dark:text-yellow-400",
    Low:      "border-blue-400/40 text-blue-600 dark:text-blue-400",
    Info:     "border-zinc-400/40 text-zinc-500 dark:text-zinc-400",
  };

  var state = {
    q: "", categories: [], severities: [], signals: [], patched: "all",
    from: "", to: "", newOnly: false,
    sort: "date", dir: "desc",
    page: 1, perPage: 25,
  };

  // ---- "new since last visit" ----
  var LAST_VISIT_KEY = "poc:lastVisit";
  var lastVisit = null;
  try { lastVisit = localStorage.getItem(LAST_VISIT_KEY); } catch (e) {}
  function stampVisit() {
    try { localStorage.setItem(LAST_VISIT_KEY, new Date().toISOString().slice(0, 10)); } catch (e) {}
  }
  window.addEventListener("pagehide", stampVisit);
  window.addEventListener("beforeunload", stampVisit);

  var fuse = null;
  var indexData = null;
  var searchMatches = null;
  var lastVisible = [];

  function setPillActive(btn, active) {
    if (active) ACTIVE.forEach(function (c) { btn.classList.add(c); });
    else ACTIVE.forEach(function (c) { btn.classList.remove(c); });
  }

  // ---- URL state ----
  function readURL() {
    var p = new URLSearchParams(window.location.search);
    state.q          = p.get("q") || "";
    state.categories = (p.get("category") || "").split(",").filter(Boolean);
    state.severities = (p.get("severity") || "").split(",").filter(Boolean);
    state.signals    = (p.get("signal") || "").split(",").filter(Boolean);
    state.patched    = p.get("patched") || "all";
    state.from       = p.get("from") || "";
    state.to         = p.get("to") || "";
    state.sort       = p.get("sort") || "date";
    state.dir        = p.get("dir") || "desc";
    state.page       = Math.max(1, parseInt(p.get("page") || "1") || 1);
    state.perPage    = parseInt(p.get("per") || "25") || 25;
    if ([25, 50, 100].indexOf(state.perPage) === -1) state.perPage = 25;
    if (fixedCategory) state.categories = [];
  }

  function writeURL() {
    var p = new URLSearchParams();
    if (state.q) p.set("q", state.q);
    if (!fixedCategory && state.categories.length) p.set("category", state.categories.join(","));
    if (state.severities.length) p.set("severity", state.severities.join(","));
    if (state.signals.length) p.set("signal", state.signals.join(","));
    if (state.patched !== "all") p.set("patched", state.patched);
    if (state.from) p.set("from", state.from);
    if (state.to) p.set("to", state.to);
    if (state.sort !== "date") p.set("sort", state.sort);
    if (state.dir !== "desc") p.set("dir", state.dir);
    if (state.page !== 1) p.set("page", String(state.page));
    if (state.perPage !== 25) p.set("per", String(state.perPage));
    var qs = p.toString();
    window.history.replaceState(null, "", window.location.pathname + (qs ? "?" + qs : ""));
  }

  // ---- Sort ----
  function sortComparator(a, b) {
    var mul = state.dir === "asc" ? 1 : -1;
    var av, bv;
    if (state.sort === "cvss") {
      av = parseFloat(a.getAttribute("data-cvss")) || 0;
      bv = parseFloat(b.getAttribute("data-cvss")) || 0;
      return (av - bv) * mul;
    }
    if (state.sort === "severity") {
      av = SEV_ORDER[a.getAttribute("data-severity")] || 0;
      bv = SEV_ORDER[b.getAttribute("data-severity")] || 0;
      return (av - bv) * mul;
    }
    if (state.sort === "priority") {
      av = parseInt(a.getAttribute("data-priority")) || 0;
      bv = parseInt(b.getAttribute("data-priority")) || 0;
      if (av !== bv) return (av - bv) * mul;
      // tie-break on date so equal-priority entries stay stable and recent-first
      av = a.getAttribute("data-date") || "";
      bv = b.getAttribute("data-date") || "";
      return (av < bv ? -1 : av > bv ? 1 : 0) * mul;
    }
    // date
    av = a.getAttribute("data-date") || "";
    bv = b.getAttribute("data-date") || "";
    return (av < bv ? -1 : av > bv ? 1 : 0) * mul;
  }

  // ---- Stats bar ----
  function updateStats(visible) {
    var el = document.getElementById("poc-stats");
    if (!el) return;
    var counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    visible.forEach(function (row) {
      var s = row.getAttribute("data-severity");
      if (s in counts) counts[s]++;
    });
    el.innerHTML = ["Critical", "High", "Medium", "Low", "Info"].map(function (s) {
      if (!counts[s]) return "";
      return '<span class="inline-flex items-center gap-1 rounded border px-2 py-0.5 font-mono text-[10px] ' + SEV_COLORS[s] + '">' +
             '<span class="font-semibold">' + counts[s] + '</span> ' + s + '</span>';
    }).join("");
  }

  // ---- Pagination ----
  function renderPagination(total, totalPages) {
    var el = document.getElementById("poc-pagination");
    if (!el) return;
    if (totalPages <= 1) { el.innerHTML = ""; return; }

    var btnCls = "rounded border border-zinc-300 px-2 py-0.5 font-mono text-xs text-zinc-600 transition hover:border-emerald-400 hover:text-emerald-600 dark:border-zinc-700 dark:text-zinc-400 dark:hover:border-emerald-400 dark:hover:text-emerald-400";
    var activeCls = "rounded border border-emerald-400 bg-emerald-400/10 px-2 py-0.5 font-mono text-xs text-emerald-600 dark:text-emerald-400";

    // Build page list with ellipsis
    var pages = [];
    var prevPg = 0;
    for (var i = 1; i <= totalPages; i++) {
      if (i === 1 || i === totalPages || Math.abs(i - state.page) <= 1) {
        if (prevPg && i - prevPg > 1) pages.push("…");
        pages.push(i);
        prevPg = i;
      }
    }

    var html = '<div class="flex items-center gap-1">';
    if (state.page > 1) {
      html += '<button type="button" class="pag-btn ' + btnCls + '" data-page="' + (state.page - 1) + '">←</button>';
    }
    pages.forEach(function (pg) {
      if (typeof pg === "string") {
        html += '<span class="px-1 text-xs text-zinc-400">' + pg + '</span>';
      } else if (pg === state.page) {
        html += '<span class="' + activeCls + '">' + pg + '</span>';
      } else {
        html += '<button type="button" class="pag-btn ' + btnCls + '" data-page="' + pg + '">' + pg + '</button>';
      }
    });
    if (state.page < totalPages) {
      html += '<button type="button" class="pag-btn ' + btnCls + '" data-page="' + (state.page + 1) + '">→</button>';
    }
    html += '</div>';

    html += '<div class="flex items-center gap-1.5 font-mono text-xs text-zinc-500 dark:text-zinc-400">';
    [25, 50, 100].forEach(function (n) {
      if (n === state.perPage) {
        html += '<span class="font-semibold text-emerald-600 dark:text-emerald-400">' + n + '</span>';
      } else {
        html += '<button type="button" class="perpage-btn underline-offset-2 hover:text-emerald-600 dark:hover:text-emerald-400 hover:underline" data-n="' + n + '">' + n + '</button>';
      }
    });
    html += '<span>/ page</span></div>';

    el.innerHTML = html;

    el.querySelectorAll(".pag-btn[data-page]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        state.page = parseInt(btn.getAttribute("data-page"));
        writeURL();
        applyFilters();
      });
    });
    el.querySelectorAll(".perpage-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        state.perPage = parseInt(btn.getAttribute("data-n"));
        state.page = 1;
        writeURL();
        applyFilters();
      });
    });
  }

  // ---- Export ----
  // One row -> one plain object. Every format below derives from this, so
  // adding a field means touching exactly one place.
  function rowToObj(row) {
    return {
      title: row.getAttribute("data-title") || "",
      cve: row.getAttribute("data-cve") || "",
      category: row.getAttribute("data-category") || "",
      severity: row.getAttribute("data-severity") || "",
      cvss: parseFloat(row.getAttribute("data-cvss")) || 0,
      epss: parseFloat(row.getAttribute("data-epss")) || 0,
      kev: row.getAttribute("data-kev") === "true",
      ransomware: row.getAttribute("data-ransomware") === "true",
      overdue: row.getAttribute("data-overdue") === "true",
      patched: row.getAttribute("data-patched") === "true",
      priority: parseInt(row.getAttribute("data-priority")) || 0,
      date: row.getAttribute("data-date") || "",
      url: location.origin + (row.getAttribute("data-permalink") || ""),
    };
  }

  function download(name, mime, text) {
    var blob = new Blob([text], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function csvCell(v) {
    var s = String(v == null ? "" : v);
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }

  function exportAs(fmt, items) {
    var stamp = new Date().toISOString().slice(0, 10);
    if (!items.length) return;

    if (fmt === "csv") {
      var cols = ["cve", "title", "category", "severity", "cvss", "epss", "kev",
                  "ransomware", "overdue", "patched", "priority", "date", "url"];
      var lines = [cols.join(",")];
      items.forEach(function (o) {
        lines.push(cols.map(function (c) { return csvCell(o[c]); }).join(","));
      });
      download("poc-archive-" + stamp + ".csv", "text/csv", lines.join("\n"));

    } else if (fmt === "json") {
      download("poc-archive-" + stamp + ".json", "application/json",
        JSON.stringify({ generated: new Date().toISOString(), count: items.length,
                         source: location.origin, pocs: items }, null, 2));

    } else if (fmt === "cves") {
      var seen = {}, out = [];
      items.forEach(function (o) {
        var m = (o.cve || "").match(/CVE-\d{4}-\d{4,7}/gi);
        if (m) m.forEach(function (c) {
          c = c.toUpperCase();
          if (!seen[c]) { seen[c] = 1; out.push(c); }
        });
      });
      download("cve-list-" + stamp + ".txt", "text/plain", out.join("\n") + "\n");

    } else if (fmt === "stix") {
      var now = new Date().toISOString();
      var objs = [{
        type: "identity", spec_version: "2.1",
        id: "identity--7c3f5a10-0000-4000-8000-poc0archive01",
        created: now, modified: now,
        name: "intelseclab PoC Archive", identity_class: "organization",
      }];
      items.forEach(function (o, i) {
        var m = (o.cve || "").match(/CVE-\d{4}-\d{4,7}/i);
        if (!m) return;
        var cve = m[0].toUpperCase();
        objs.push({
          type: "vulnerability", spec_version: "2.1",
          id: "vulnerability--" + uuidFrom(cve + i),
          created: now, modified: now,
          created_by_ref: objs[0].id,
          name: cve,
          description: o.title,
          external_references: [
            { source_name: "cve", external_id: cve },
            { source_name: "poc-archive", url: o.url },
          ],
          labels: [o.severity.toLowerCase()].concat(
            o.kev ? ["cisa-kev"] : []).concat(
            o.ransomware ? ["ransomware"] : []),
        });
      });
      download("poc-archive-stix-" + stamp + ".json", "application/json",
        JSON.stringify({ type: "bundle", id: "bundle--" + uuidFrom(stamp), objects: objs }, null, 2));
    }
  }

  // Deterministic RFC-4122-shaped v4 id from a seed (no crypto dependency).
  function uuidFrom(seed) {
    var h = 0x811c9dc5;
    for (var i = 0; i < seed.length; i++) {
      h ^= seed.charCodeAt(i);
      h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
    }
    var hex = "";
    for (var j = 0; j < 8; j++) {
      h = (h * 1664525 + 1013904223) >>> 0;
      hex += ("00000000" + h.toString(16)).slice(-8);
    }
    return hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-4" + hex.slice(13, 16) +
           "-a" + hex.slice(17, 20) + "-" + hex.slice(20, 32);
  }

  // ---- Filtering + sorting + pagination ----
  function applyFilters() {
    // Determine which rows pass the current filters
    var matchSet = new Set();
    rows.forEach(function (row) {
      var cat     = row.getAttribute("data-category");
      var sev     = row.getAttribute("data-severity");
      var patched = row.getAttribute("data-patched");
      var date    = row.getAttribute("data-date");
      var link    = row.getAttribute("data-permalink");
      var ok = true;
      if (state.categories.length && state.categories.indexOf(cat) === -1) ok = false;
      if (ok && state.severities.length && state.severities.indexOf(sev) === -1) ok = false;
      if (ok && state.patched !== "all" && patched !== state.patched) ok = false;
      if (ok && state.from && date < state.from) ok = false;
      if (ok && state.to && date > state.to) ok = false;
      // Signals are AND-ed: "KEV + Ransomware" means both must hold.
      if (ok && state.signals.length) {
        for (var si = 0; si < state.signals.length; si++) {
          var sg = state.signals[si];
          if (sg === "kev" && row.getAttribute("data-kev") !== "true") { ok = false; break; }
          if (sg === "ransomware" && row.getAttribute("data-ransomware") !== "true") { ok = false; break; }
          if (sg === "overdue" && row.getAttribute("data-overdue") !== "true") { ok = false; break; }
          if (sg === "epss" && (parseFloat(row.getAttribute("data-epss")) || 0) < 0.5) { ok = false; break; }
        }
      }
      if (ok && state.newOnly && lastVisit && date <= lastVisit) ok = false;
      if (ok && searchMatches && !searchMatches.has(link)) ok = false;
      if (ok) matchSet.add(row);
    });

    // Sort all rows; reorder DOM so visible rows appear in sort order
    var sorted = rows.slice().sort(sortComparator);
    var visible = sorted.filter(function (r) { return matchSet.has(r); });

    updateStats(visible);
    lastVisible = visible;

    var total = visible.length;
    var totalPages = Math.max(1, Math.ceil(total / state.perPage));
    if (state.page > totalPages) state.page = totalPages;

    var start = (state.page - 1) * state.perPage;
    var pageSet = new Set(visible.slice(start, start + state.perPage));

    sorted.forEach(function (row) {
      rowsEl.appendChild(row);
      row.classList.toggle("hidden", !pageSet.has(row));
    });

    if (countEl) countEl.textContent = String(total);
    if (emptyEl) emptyEl.classList.toggle("hidden", total !== 0);
    if (rowsEl)  rowsEl.classList.toggle("hidden", total === 0);
    renderPagination(total, totalPages);
  }

  // ---- Search ----
  function runSearch() {
    if (!state.q) { searchMatches = null; applyFilters(); return; }
    if (!indexData) { applyFilters(); return; }

    // CVE-pattern queries: exact substring match — fuzzy produces false positives
    if (/^cve[-\s]?\d{4}[-\s]?\d+/i.test(state.q.trim())) {
      var norm = state.q.trim().toLowerCase().replace(/\s+/g, "-");
      searchMatches = new Set(
        indexData
          .filter(function (item) {
            return (item.cve || "").toLowerCase().indexOf(norm) !== -1;
          })
          .map(function (item) { return item.permalink; })
      );
      applyFilters();
      return;
    }

    var results = fuse.search(state.q);
    searchMatches = new Set(results.map(function (r) { return r.item.permalink; }));
    applyFilters();
  }

  // update() is called for every filter/sort/search change; always resets to page 1
  function update() {
    state.page = 1;
    writeURL();
    runSearch();
  }

  // ---- Sync controls to state ----
  function updateActiveIndicator() {
    var n = 0;
    if (!fixedCategory) n += state.categories.length;
    n += state.severities.length;
    n += state.signals.length;
    if (state.patched !== "all") n++;
    if (state.from || state.to) n++;
    if (state.newOnly) n++;
    if (state.sort !== "date") n++;

    var badge = document.getElementById("filter-count");
    if (badge) {
      if (n > 0) { badge.textContent = n + " filter" + (n > 1 ? "s" : ""); badge.classList.remove("hidden"); }
      else badge.classList.add("hidden");
    }
    if (clearEl) clearEl.classList.toggle("hidden", n === 0);

    // Highlight date inputs when they hold a value
    var activeInputCls = "!border-emerald-400";
    if (fromEl) fromEl.classList.toggle(activeInputCls, !!state.from);
    if (toEl)   toEl.classList.toggle(activeInputCls,   !!state.to);
  }

  function syncControls() {
    if (searchEl) searchEl.value = state.q;
    if (fromEl) fromEl.value = state.from;
    if (toEl)   toEl.value   = state.to;

    document.querySelectorAll("#filter-category .filter-pill").forEach(function (btn) {
      setPillActive(btn, state.categories.indexOf(btn.getAttribute("data-value")) !== -1);
    });
    document.querySelectorAll("#filter-severity .filter-pill").forEach(function (btn) {
      setPillActive(btn, state.severities.indexOf(btn.getAttribute("data-value")) !== -1);
    });
    document.querySelectorAll("#filter-signal .filter-pill").forEach(function (btn) {
      setPillActive(btn, state.signals.indexOf(btn.getAttribute("data-value")) !== -1);
    });
    document.querySelectorAll("#filter-patched .filter-radio").forEach(function (btn) {
      setPillActive(btn, btn.getAttribute("data-value") === state.patched);
    });
    document.querySelectorAll("#sort-controls .sort-btn").forEach(function (btn) {
      setPillActive(btn, btn.getAttribute("data-sort") === state.sort);
    });
    var dirBtn = document.getElementById("sort-dir");
    if (dirBtn) dirBtn.textContent = state.dir === "asc" ? "↑" : "↓";

    updateActiveIndicator();
  }

  // ---- Events ----
  document.querySelectorAll("#filter-category .filter-pill").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var v = btn.getAttribute("data-value");
      var i = state.categories.indexOf(v);
      if (i === -1) state.categories.push(v); else state.categories.splice(i, 1);
      setPillActive(btn, i === -1);
      update();
    });
  });

  document.querySelectorAll("#filter-severity .filter-pill").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var v = btn.getAttribute("data-value");
      var i = state.severities.indexOf(v);
      if (i === -1) state.severities.push(v); else state.severities.splice(i, 1);
      setPillActive(btn, i === -1);
      update();
    });
  });

  document.querySelectorAll("#filter-signal .filter-pill").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var v = btn.getAttribute("data-value");
      var i = state.signals.indexOf(v);
      if (i === -1) state.signals.push(v); else state.signals.splice(i, 1);
      setPillActive(btn, i === -1);
      update();
    });
  });

  // Export menu
  var exportToggle = document.getElementById("export-toggle");
  var exportMenu = document.getElementById("export-menu");
  if (exportToggle && exportMenu) {
    exportToggle.addEventListener("click", function (e) {
      e.stopPropagation();
      exportMenu.classList.toggle("hidden");
    });
    document.addEventListener("click", function () { exportMenu.classList.add("hidden"); });
    exportMenu.addEventListener("click", function (e) { e.stopPropagation(); });
    exportMenu.querySelectorAll(".export-opt").forEach(function (btn) {
      btn.addEventListener("click", function () {
        exportAs(btn.getAttribute("data-fmt"), lastVisible.map(rowToObj));
        exportMenu.classList.add("hidden");
      });
    });
  }

  // "N new since last visit" — click to filter down to just those
  var newSinceEl = document.getElementById("new-since");
  if (newSinceEl) {
    newSinceEl.addEventListener("click", function () {
      state.newOnly = !state.newOnly;
      newSinceEl.classList.toggle("ring-1", state.newOnly);
      newSinceEl.classList.toggle("ring-emerald-400", state.newOnly);
      update();
    });
  }

  document.querySelectorAll("#filter-patched .filter-radio").forEach(function (btn) {
    btn.addEventListener("click", function () {
      state.patched = btn.getAttribute("data-value");
      document.querySelectorAll("#filter-patched .filter-radio").forEach(function (b) {
        setPillActive(b, b === btn);
      });
      update();
    });
  });

  // Sort field buttons — clicking active field toggles direction
  document.querySelectorAll("#sort-controls .sort-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var s = btn.getAttribute("data-sort");
      if (state.sort === s) {
        state.dir = state.dir === "asc" ? "desc" : "asc";
      } else {
        state.sort = s;
        state.dir = "desc";
      }
      syncControls();
      update();
    });
  });

  var dirBtn = document.getElementById("sort-dir");
  if (dirBtn) {
    dirBtn.addEventListener("click", function () {
      state.dir = state.dir === "asc" ? "desc" : "asc";
      syncControls();
      update();
    });
  }

  if (searchEl) {
    searchEl.addEventListener("input", function () {
      state.q = searchEl.value.trim();
      update();
    });
  }
  if (fromEl) fromEl.addEventListener("change", function () { state.from = fromEl.value; update(); });
  if (toEl)   toEl.addEventListener("change",   function () { state.to   = toEl.value;   update(); });

  // "/" focuses search from anywhere on the page
  document.addEventListener("keydown", function (e) {
    if (e.key === "/" && document.activeElement !== searchEl &&
        ["INPUT", "TEXTAREA", "SELECT"].indexOf(document.activeElement.tagName) === -1) {
      e.preventDefault();
      if (searchEl) { searchEl.focus(); searchEl.select(); }
    }
  });

  if (clearEl) {
    clearEl.addEventListener("click", function () {
      state.q = ""; state.categories = []; state.severities = []; state.signals = [];
      state.patched = "all"; state.from = ""; state.to = ""; state.newOnly = false;
      state.sort = "date"; state.dir = "desc";
      state.page = 1; state.perPage = 25;
      searchMatches = null;
      if (newSinceEl) newSinceEl.classList.remove("ring-1", "ring-emerald-400");
      syncControls();
      update();
    });
  }

  // ---- Init ----
  // Flag entries added since the previous visit, before the first render.
  if (lastVisit) {
    var newCount = 0;
    rows.forEach(function (row) {
      if ((row.getAttribute("data-date") || "") > lastVisit) {
        newCount++;
        var b = row.querySelector(".poc-new-badge");
        if (b) b.classList.remove("hidden");
      }
    });
    if (newCount && newSinceEl) {
      newSinceEl.textContent = "✨ " + newCount + " new since last visit";
      newSinceEl.classList.remove("hidden");
    }
  }

  readURL();
  syncControls();
  applyFilters();

  if (typeof Fuse !== "undefined" && indexURL) {
    fetch(indexURL)
      .then(function (r) { return r.json(); })
      .then(function (data) {
        indexData = data;
        fuse = new Fuse(data, {
          includeScore: false,
          threshold: 0.2,
          ignoreLocation: true,
          minMatchCharLength: 3,
          keys: [
            { name: "title",            weight: 0.4 },
            { name: "tags",             weight: 0.3 },
            { name: "affected_product", weight: 0.2 },
            { name: "summary",          weight: 0.1 },
          ],
        });
        if (state.q) runSearch();
      })
      .catch(function () {});
  }
})();
