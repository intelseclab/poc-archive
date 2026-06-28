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

  var state = {
    q: "",
    categories: [],
    severities: [],
    patched: "all",
    from: "",
    to: "",
  };

  var fuse = null;
  var searchMatches = null; // Set of permalinks, or null when no query

  function setPillActive(btn, active) {
    if (active) ACTIVE.forEach(function (c) { btn.classList.add(c); });
    else ACTIVE.forEach(function (c) { btn.classList.remove(c); });
  }

  // ---- URL state ----
  function readURL() {
    var p = new URLSearchParams(window.location.search);
    state.q = p.get("q") || "";
    state.categories = (p.get("category") || "").split(",").filter(Boolean);
    state.severities = (p.get("severity") || "").split(",").filter(Boolean);
    state.patched = p.get("patched") || "all";
    state.from = p.get("from") || "";
    state.to = p.get("to") || "";
    if (fixedCategory) state.categories = [];
  }

  function writeURL() {
    var p = new URLSearchParams();
    if (state.q) p.set("q", state.q);
    if (!fixedCategory && state.categories.length) p.set("category", state.categories.join(","));
    if (state.severities.length) p.set("severity", state.severities.join(","));
    if (state.patched !== "all") p.set("patched", state.patched);
    if (state.from) p.set("from", state.from);
    if (state.to) p.set("to", state.to);
    var qs = p.toString();
    var url = window.location.pathname + (qs ? "?" + qs : "");
    window.history.replaceState(null, "", url);
  }

  // ---- Apply state to controls ----
  function syncControls() {
    if (searchEl) searchEl.value = state.q;
    if (fromEl) fromEl.value = state.from;
    if (toEl) toEl.value = state.to;

    document.querySelectorAll("#filter-category .filter-pill").forEach(function (btn) {
      setPillActive(btn, state.categories.indexOf(btn.getAttribute("data-value")) !== -1);
    });
    document.querySelectorAll("#filter-severity .filter-pill").forEach(function (btn) {
      setPillActive(btn, state.severities.indexOf(btn.getAttribute("data-value")) !== -1);
    });
    document.querySelectorAll("#filter-patched .filter-radio").forEach(function (btn) {
      setPillActive(btn, btn.getAttribute("data-value") === state.patched);
    });
  }

  // ---- Filtering ----
  function applyFilters() {
    var visible = 0;
    rows.forEach(function (row) {
      var cat = row.getAttribute("data-category");
      var sev = row.getAttribute("data-severity");
      var patched = row.getAttribute("data-patched");
      var date = row.getAttribute("data-date");
      var link = row.getAttribute("data-permalink");

      var ok = true;
      if (state.categories.length && state.categories.indexOf(cat) === -1) ok = false;
      if (ok && state.severities.length && state.severities.indexOf(sev) === -1) ok = false;
      if (ok && state.patched !== "all" && patched !== state.patched) ok = false;
      if (ok && state.from && date < state.from) ok = false;
      if (ok && state.to && date > state.to) ok = false;
      if (ok && searchMatches && !searchMatches.has(link)) ok = false;

      row.classList.toggle("hidden", !ok);
      if (ok) visible++;
    });

    if (countEl) countEl.textContent = String(visible);
    if (emptyEl) emptyEl.classList.toggle("hidden", visible !== 0);
    if (rowsEl) rowsEl.classList.toggle("hidden", visible === 0);
  }

  function runSearch() {
    if (!state.q) { searchMatches = null; applyFilters(); return; }
    if (!fuse) { applyFilters(); return; } // index not ready yet
    var results = fuse.search(state.q);
    searchMatches = new Set(results.map(function (r) { return r.item.permalink; }));
    applyFilters();
  }

  function update() {
    writeURL();
    runSearch();
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

  document.querySelectorAll("#filter-patched .filter-radio").forEach(function (btn) {
    btn.addEventListener("click", function () {
      state.patched = btn.getAttribute("data-value");
      document.querySelectorAll("#filter-patched .filter-radio").forEach(function (b) {
        setPillActive(b, b === btn);
      });
      update();
    });
  });

  if (searchEl) {
    searchEl.addEventListener("input", function () {
      state.q = searchEl.value.trim();
      update();
    });
  }
  if (fromEl) fromEl.addEventListener("change", function () { state.from = fromEl.value; update(); });
  if (toEl) toEl.addEventListener("change", function () { state.to = toEl.value; update(); });

  if (clearEl) {
    clearEl.addEventListener("click", function () {
      state.q = "";
      state.categories = [];
      state.severities = [];
      state.patched = "all";
      state.from = "";
      state.to = "";
      searchMatches = null;
      syncControls();
      update();
    });
  }

  // ---- Init ----
  readURL();
  syncControls();
  applyFilters();

  // Load Fuse index lazily
  if (typeof Fuse !== "undefined" && indexURL) {
    fetch(indexURL)
      .then(function (r) { return r.json(); })
      .then(function (data) {
        fuse = new Fuse(data, {
          includeScore: false,
          threshold: 0.35,
          ignoreLocation: true,
          keys: [
            { name: "title", weight: 0.4 },
            { name: "cve", weight: 0.3 },
            { name: "tags", weight: 0.15 },
            { name: "affected_product", weight: 0.15 },
          ],
        });
        if (state.q) runSearch();
      })
      .catch(function () { /* search index unavailable; filters still work */ });
  }
})();
