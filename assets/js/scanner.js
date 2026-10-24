/* ==========================================================================
   Vortexis Threat Lab — client-side demo scanner
   --------------------------------------------------------------------------
   Bu sayfa gerçek bir antivirüs motoru değildir. Hash/URL/dosya adı üzerinden
   deterministik, simüle edilmiş bir rapor üretir. Gerçek tarama için sunucu
   tarafında VirusTotal, MetaDefender veya kendi tarama servisiniz gerekir.
   ========================================================================== */
(function () {
  "use strict";

  const CFG = window.VORTEXIS || {};
  const SCAN = CFG.scanner || {};
  const STORAGE_KEY = SCAN.storageKey || "vortexis.scans.v1";
  const MAX_RECENT = SCAN.maxRecent || 8;
  const MAX_FILE = SCAN.maxFileSize || 104857600;
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const toast = (msg, type) => window.VortexisUI && window.VortexisUI.toast(msg, type);
  const icon = (name, cls) => `<svg class="icon ${cls || ""}" aria-hidden="true"><use href="assets/icons.svg#${name}"></use></svg>`;

  const VENDORS = [
    "Microsoft", "Google", "Kaspersky", "BitDefender", "ESET-NOD32", "Sophos",
    "Avast", "AVG", "Avira", "McAfee", "Symantec", "Trend Micro",
    "F-Secure", "G Data", "Fortinet", "Dr.Web", "VIPRE", "Webroot",
    "Panda", "Ikarus", "Cylance", "CrowdStrike", "SentinelOne", "Malwarebytes"
  ];

  const DETECTIONS = [
    "Trojan:Win32/Wacatac.B!ml",
    "Gen:Variant.MSILKrypt.12",
    "PUA:Win32/Presenoker",
    "HEUR:Trojan.Win32.Generic",
    "Win32:Malware-gen",
    "Trojan.GenericKD.48219331",
    "ML.Attribute.HighConfidence",
    "Suspicious.Cloud.9",
    "Backdoor.Win32.Agent",
    "Ransom:Win32/StopCrypt",
    "HackTool:Win32/Mimikatz",
    "Worm.Win32.AutoRun"
  ];

  const SUSPICIOUS = [
    "Heur.BZC.QLSX.3",
    "Suspicious.Packed",
    "PUA.Riskware",
    "Low confidence signal",
    "Generic.ML",
    "Unwanted application"
  ];

  const SAMPLE_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  const EICAR_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

  let currentResult = null;
  let busy = false;
  let selectedFile = null;
  let activeType = "hash";
  let els = {};

  /* ---------------------------------------------------------------- utils */
  const escapeHtml = (s) =>
    String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");

  const hashString = (str) => {
    let h = 2166136261;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return h >>> 0;
  };

  const mulberry32 = (seed) => () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };

  const formatBytes = (bytes) => {
    if (bytes == null || isNaN(bytes)) return "—";
    if (bytes === 0) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
    return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  };

  const formatDate = (date, withTime) => {
    try {
      return new Date(date).toLocaleDateString("tr-TR", {
        day: "2-digit",
        month: "short",
        year: "numeric",
        ...(withTime ? { hour: "2-digit", minute: "2-digit" } : {})
      });
    } catch (_) {
      return "—";
    }
  };

  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  const sha256 = async (buffer) => {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error("Tarayıcınız dosya hash'i hesaplamayı desteklemiyor.");
    }
    const digest = await crypto.subtle.digest("SHA-256", buffer);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  };

  const looksLikeHash = (q) => /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(q);
  const looksLikeUrl = (q) => /^(https?:\/\/)?([\w-]+\.)+[a-z]{2,}(\/\S*)?$/i.test(q);

  /* ---------------------------------------------------------------- classify */
  function verdictFor(query, type) {
    const q = String(query || "").toLowerCase();
    if (q.includes(EICAR_HASH) || q.includes("eicar")) return "malicious";
    if (q.includes("mimikatz") || q.includes("ransom") || q.includes("trojan") || q.includes("malware")) return "malicious";
    if (q.includes("free-robux") || q.includes("login-verify") || q.includes("update-") || q.includes("crypto-")) return "suspicious";
    if (!q || q === SAMPLE_HASH || q.includes("clean") || q.includes("vortexis")) return "clean";

    const rng = mulberry32(hashString(`${type}:${q}`));
    const r = rng();
    if (r < 0.68) return "clean";
    if (r < 0.88) return "suspicious";
    return "malicious";
  }

  function buildResult(query, type, fileMeta) {
    const q = String(query || "");
    const verdict = verdictFor(q, type);
    const seed = hashString(`${type}:${q}:${verdict}`);
    const rng = mulberry32(seed);
    const total = VENDORS.length;

    let detections;
    let risk;
    if (verdict === "clean") {
      detections = 0;
      risk = Math.floor(2 + rng() * 9);
    } else if (verdict === "suspicious") {
      detections = Math.floor(2 + rng() * 5);
      risk = Math.floor(26 + rng() * 29);
    } else {
      detections = Math.floor(14 + rng() * 9);
      risk = Math.floor(76 + rng() * 23);
    }

    const flagged = new Set();
    while (flagged.size < detections) flagged.add(Math.floor(rng() * total));

    const vendors = VENDORS.map((name, i) => {
      const bad = flagged.has(i);
      let status = "clean";
      let result = "Temiz";
      if (bad) {
        status = verdict === "suspicious" ? "suspicious" : "malicious";
        result = status === "suspicious" ? SUSPICIOUS[Math.floor(rng() * SUSPICIOUS.length)] : DETECTIONS[Math.floor(rng() * DETECTIONS.length)];
      }
      return { name, status, result };
    });

    const now = new Date();
    const firstSeen = new Date(now.getTime() - Math.floor(rng() * 420) * 86400000);
    const fileName =
      fileMeta && fileMeta.name
        ? fileMeta.name
        : type === "url"
          ? (() => {
              try {
                return new URL(/^https?:\/\//i.test(q) ? q : `https://${q}`).hostname;
              } catch (_) {
                return q.slice(0, 48) || "URL taraması";
              }
            })()
          : looksLikeHash(q)
            ? "bilinmeyen-dosya"
            : q.slice(0, 48) || "bilinmeyen-dosya";

    const fileType =
      fileMeta && fileMeta.type
        ? fileMeta.type
        : type === "url"
          ? "URL"
          : looksLikeHash(q)
            ? "SHA-256 özeti"
            : "Serbest metin";

    const tags =
      verdict === "clean"
        ? ["pe32", "windows", "signed", "low-risk"]
        : verdict === "suspicious"
          ? ["pe32", "packed", "unsigned", "needs-review"]
          : ["pe32", "packed", "persistence", "unsigned", "high-risk"];

    const community =
      verdict === "clean"
        ? { harmless: Math.floor(38 + rng() * 80), malicious: Math.floor(rng() * 2) }
        : verdict === "suspicious"
          ? { harmless: Math.floor(4 + rng() * 14), malicious: Math.floor(3 + rng() * 8) }
          : { harmless: Math.floor(1 + rng() * 9), malicious: Math.floor(18 + rng() * 70) };

    return {
      query: q,
      type,
      fileName,
      fileType,
      size: fileMeta && fileMeta.size != null ? formatBytes(fileMeta.size) : type === "url" ? "—" : looksLikeHash(q) ? "—" : "—",
      hash: looksLikeHash(q) ? q.toLowerCase() : type === "url" ? q : fileMeta && fileMeta.hash ? fileMeta.hash : "",
      verdict,
      risk,
      detections,
      total,
      vendors,
      firstSeen: firstSeen.toISOString(),
      lastAnalysis: now.toISOString(),
      signature: verdict === "clean" ? "Geçerli dijital imza" : verdict === "suspicious" ? "İmza doğrulanamadı" : "İmzasız / gömülü",
      tags,
      community,
      time: now.toISOString()
    };
  }

  /* ---------------------------------------------------------------- render */
  function verdictLabel(v) {
    return v === "malicious" ? "Zararlı" : v === "suspicious" ? "Şüpheli" : "Temiz";
  }

  function verdictIcon(v) {
    return v === "malicious" ? "alert-triangle" : v === "suspicious" ? "alert-triangle" : "shield-check";
  }

  function renderVendors(result) {
    const body = $("[data-vendor-body]");
    if (!body) return;
    body.innerHTML = result.vendors
      .map(
        (v) => `<tr data-vendor-row data-status="${v.status}" data-name="${escapeHtml(v.name.toLowerCase())} ${escapeHtml(v.result.toLowerCase())}">
          <td class="vendor-name">${escapeHtml(v.name)}</td>
          <td class="vendor-result">${escapeHtml(v.result)}</td>
          <td><span class="vendor-status vendor-status--${v.status}"><span></span>${v.status === "clean" ? "Temiz" : v.status === "suspicious" ? "Şüpheli" : "Tespit"}</span></td>
        </tr>`
      )
      .join("");
    const count = $("[data-vendor-count]");
    if (count) count.textContent = String(result.total);
    const det = $("[data-detection-count]");
    if (det) det.textContent = String(result.detections);
    filterVendors();
  }

  function filterVendors() {
    const input = $("[data-vendor-search]");
    const only = $("[data-only-detections]");
    const rows = $$("[data-vendor-row]");
    const q = input ? input.value.trim().toLowerCase() : "";
    const onlyBad = only ? only.checked : false;
    let shown = 0;
    rows.forEach((row) => {
      const bad = row.dataset.status !== "clean";
      const match = (!q || row.dataset.name.includes(q)) && (!onlyBad || bad);
      row.hidden = !match;
      if (match) shown++;
    });
    const counter = $("[data-visible-vendors]");
    if (counter) counter.textContent = `${shown} / ${rows.length}`;
  }

  function renderResult(result, isSample) {
    currentResult = result;
    const panel = $("[data-scan-result]");
    if (!panel) return;
    panel.hidden = false;
    panel.classList.add("is-active");

    const verdictEls = $$("[data-result-verdict]");
    verdictEls.forEach((el) => {
      el.textContent = verdictLabel(result.verdict);
      el.className = `verdict-badge verdict-badge--${result.verdict}`;
      el.innerHTML = `${icon(verdictIcon(result.verdict))}<span>${verdictLabel(result.verdict)}</span>`;
    });

    const ratio = $("[data-result-ratio]");
    if (ratio) ratio.textContent = `${result.detections} / ${result.total}`;
    const ratioLabel = $("[data-result-ratio-label]");
    if (ratioLabel) ratioLabel.textContent = result.detections === 0 ? "motor tespit etmedi" : "motor tespit etti";

    const gauge = $("[data-risk-gauge]");
    if (gauge) {
      gauge.style.setProperty("--score", result.risk);
      gauge.style.setProperty("--gauge-color", result.verdict === "malicious" ? "var(--danger)" : result.verdict === "suspicious" ? "var(--amber)" : "var(--green)");
    }
    const riskScore = $("[data-risk-score]");
    if (riskScore) riskScore.textContent = String(result.risk);
    const riskLabel = $("[data-risk-label]");
    if (riskLabel) riskLabel.textContent = result.verdict === "malicious" ? "Yüksek risk" : result.verdict === "suspicious" ? "Orta risk" : "Düşük risk";

    const set = (sel, val) => $$(sel).forEach((el) => (el.textContent = val));
    set("[data-result-name]", result.fileName);
    set("[data-result-type]", result.fileType);
    set("[data-result-size]", result.size);
    set("[data-result-first]", formatDate(result.firstSeen));
    set("[data-result-last]", formatDate(result.lastAnalysis, true));
    set("[data-result-signature]", result.signature);
    set("[data-result-hash]", result.hash || "—");
    set("[data-result-query]", result.query);

    const sampleBadge = $("[data-sample-badge]");
    if (sampleBadge) sampleBadge.hidden = !isSample;

    const tags = $("[data-result-tags]");
    if (tags) {
      tags.innerHTML = result.tags.map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join("");
    }

    const community = $("[data-community]");
    if (community) {
      const totalVotes = result.community.harmless + result.community.malicious || 1;
      const harmlessPct = Math.round((result.community.harmless / totalVotes) * 100);
      community.innerHTML = `
        <div class="community-row"><span>Güvenli</span><strong>${result.community.harmless}</strong></div>
        <div class="community-bar"><span style="width:${harmlessPct}%"></span></div>
        <div class="community-row"><span>Zararlı</span><strong>${result.community.malicious}</strong></div>
        <div class="community-bar community-bar--danger"><span style="width:${100 - harmlessPct}%"></span></div>`;
    }

    renderVendors(result);

    const download = $("[data-download-report]");
    if (download) download.dataset.ready = "true";

    if (window.innerWidth < 760) {
      window.setTimeout(() => panel.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
    }
  }

  /* ---------------------------------------------------------------- recent */
  function readScans() {
    try {
      const raw = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
      return Array.isArray(raw) ? raw : [];
    } catch (_) {
      return [];
    }
  }

  function saveScan(result) {
    const scans = readScans();
    const entry = {
      query: result.query,
      type: result.type,
      name: result.fileName,
      verdict: result.verdict,
      detections: result.detections,
      total: result.total,
      risk: result.risk,
      time: result.time
    };
    const filtered = scans.filter((s) => !(s.query === entry.query && s.type === entry.type));
    filtered.unshift(entry);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(filtered.slice(0, MAX_RECENT)));
    } catch (_) {}
    renderRecent();
  }

  function renderRecent() {
    const body = $("[data-recent-body]");
    if (!body) return;
    const scans = readScans();
    const empty = $("[data-recent-empty]");
    if (!scans.length) {
      body.innerHTML = "";
      if (empty) empty.hidden = false;
      return;
    }
    if (empty) empty.hidden = true;
    body.innerHTML = scans
      .map(
        (s, i) => `<tr>
          <td><span class="scan-type-icon">${escapeHtml((s.type || "hash").toUpperCase())}</span><span class="scan-query">${escapeHtml(s.name || s.query || "—")}</span></td>
          <td><span class="verdict-dot verdict-dot--${escapeHtml(s.verdict || "clean")}"></span>${escapeHtml(verdictLabel(s.verdict))}</td>
          <td>${escapeHtml(String(s.detections ?? 0))}/${escapeHtml(String(s.total ?? 0))}</td>
          <td class="recent-time">${escapeHtml(formatDate(s.time, true))}</td>
          <td><button class="btn btn-xs btn-ghost" type="button" data-rescan="${i}">${icon("refresh")} Tekrar</button></td>
        </tr>`
      )
      .join("");
  }

  /* ---------------------------------------------------------------- progress */
  async function progressRun(steps, work) {
    const box = $("[data-scan-progress]");
    const bar = $("[data-progress-bar]");
    const label = $("[data-progress-label]");
    const list = $("[data-progress-steps]");
    if (box) {
      box.hidden = false;
      box.classList.add("is-active");
    }
    const resultPanel = $("[data-scan-result]");
    if (resultPanel) {
      resultPanel.hidden = true;
      resultPanel.classList.remove("is-active");
    }
    if (list) {
      list.innerHTML = steps.map((s, i) => `<li data-step="${i}"><span class="step-dot"></span>${escapeHtml(s)}</li>`).join("");
    }
    const total = steps.length;
    for (let i = 0; i < total; i++) {
      const li = list ? $(`[data-step="${i}"]`, list) : null;
      if (li) li.classList.add("is-active");
      if (label) label.textContent = steps[i];
      if (bar) bar.style.width = `${Math.round(((i + 0.35) / total) * 100)}%`;
      await delay(360 + Math.random() * 180);
      if (li) {
        li.classList.remove("is-active");
        li.classList.add("is-done");
      }
    }
    if (bar) bar.style.width = "100%";
    if (label) label.textContent = "Rapor hazırlanıyor…";
    const result = await work();
    await delay(260);
    if (box) {
      box.classList.remove("is-active");
      box.hidden = true;
    }
    if (bar) bar.style.width = "0%";
    return result;
  }

  /* ---------------------------------------------------------------- scan */
  async function runScan(query, type, file) {
    if (busy) return;
    if (type !== "file" && !String(query || "").trim()) {
      toast("Taramak için bir hash, URL veya dosya adı girin.", "error");
      return;
    }
    if (type === "file" && !file) {
      toast("Önce bir dosya seçin veya sürükleyip bırakın.", "error");
      return;
    }
    if (type === "url" && query && !looksLikeUrl(query)) {
      toast("Geçerli bir URL veya alan adı girin.", "error");
      return;
    }
    if (file && file.size > MAX_FILE) {
      toast(`Dosya boyutu ${formatBytes(MAX_FILE)} sınırını aşıyor.`, "error");
      return;
    }

    busy = true;
    const submit = $("[data-scan-submit]");
    if (submit) submit.disabled = true;
    try {
      let fileMeta = null;
      let hashQuery = query;
      const steps =
        type === "file"
          ? ["Dosya okunuyor", "SHA-256 hesaplanıyor", "24 motor sorgulanıyor", "Topluluk sinyalleri", "Rapor hazırlanıyor"]
          : ["Girdi doğrulanıyor", "24 motor sorgulanıyor", "İmza veritabanı", "Topluluk sinyalleri", "Rapor hazırlanıyor"];

      const result = await progressRun(steps, async () => {
        if (type === "file") {
          const buffer = await file.arrayBuffer();
          const hash = await sha256(buffer);
          fileMeta = { name: file.name, size: file.size, type: file.type || "Bilinmeyen dosya", hash };
          hashQuery = hash;
        }
        return buildResult(hashQuery, type, fileMeta);
      });

      renderResult(result, false);
      saveScan(result);
      const input = $("[data-scan-input]");
      if (input && type !== "file") input.value = query;
      toast("Tarama tamamlandı.", result.verdict === "malicious" ? "error" : "success");
    } catch (err) {
      toast(err.message || "Tarama sırasında bir hata oluştu.", "error");
    } finally {
      busy = false;
      if (submit) submit.disabled = false;
    }
  }

  /* ---------------------------------------------------------------- type tabs */
  function setType(type) {
    activeType = type;
    $$("[data-scan-type]").forEach((btn) => {
      const on = btn.dataset.scanType === type;
      btn.classList.toggle("is-active", on);
      btn.setAttribute("aria-selected", on ? "true" : "false");
    });
    const inputRow = $("[data-input-row]");
    const drop = $("[data-drop-zone]");
    const input = $("[data-scan-input]");
    const label = $("[data-scan-label]");
    const submit = $("[data-scan-submit]");
    const hint = $("[data-scan-hint]");
    if (inputRow) {
      inputRow.hidden = false;
      inputRow.classList.toggle("is-file", type === "file");
    }
    if (drop) drop.hidden = type !== "file";
    if (label) label.hidden = type === "file";
    if (input) {
      input.hidden = type === "file";
      input.value = type === "file" ? "" : input.value;
      input.placeholder =
        type === "hash"
          ? "SHA-256, SHA-1 veya MD5 hash girin…"
          : type === "url"
            ? "https://ornek.com veya alan adı girin…"
            : "Dosya seçin…";
    }
    if (submit) {
      submit.innerHTML =
        type === "file"
          ? `${icon("file")} Dosyayı tara`
          : `${icon("search")} Taramayı başlat`;
    }
    if (hint) {
      hint.textContent =
        type === "hash"
          ? "64 karakterlik SHA-256, 40 karakterlik SHA-1 veya 32 karakterlik MD5 desteklenir."
          : type === "url"
            ? "URL'ler yalnızca ön inceleme amaçlıdır; sayfa içeriği indirilmez."
            : "Dosya tarayıcınızdan ayrılmaz; SHA-256 özeti yerel olarak hesaplanır.";
    }
    if (type === "file") {
      const nameEl = $("[data-file-name]");
      if (nameEl) nameEl.textContent = selectedFile ? `${selectedFile.name} · ${formatBytes(selectedFile.size)}` : "Henüz dosya seçilmedi";
    }
  }

  /* ---------------------------------------------------------------- init */
  function init() {
    const root = $("[data-scanner-app]");
    if (!root) return;
    els = {
      form: $("[data-scan-form]", root),
      input: $("[data-scan-input]", root),
      result: $("[data-scan-result]", root)
    };

    $$("[data-scan-type]", root).forEach((btn) => btn.addEventListener("click", () => setType(btn.dataset.scanType)));
    setType("hash");

    const drop = $("[data-drop-zone]", root);
    const fileInput = $("[data-file-input]", root);
    if (drop && fileInput) {
      drop.addEventListener("click", () => fileInput.click());
      drop.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          fileInput.click();
        }
      });
      ["dragenter", "dragover"].forEach((ev) =>
        drop.addEventListener(ev, (e) => {
          e.preventDefault();
          drop.classList.add("is-dragover");
        })
      );
      ["dragleave", "drop"].forEach((ev) =>
        drop.addEventListener(ev, (e) => {
          e.preventDefault();
          drop.classList.remove("is-dragover");
        })
      );
      drop.addEventListener("drop", (e) => {
        const file = e.dataTransfer.files && e.dataTransfer.files[0];
        if (!file) return;
        selectedFile = file;
        const nameEl = $("[data-file-name]");
        if (nameEl) nameEl.textContent = `${file.name} · ${formatBytes(file.size)}`;
        toast(`${file.name} seçildi.`, "success");
      });
      fileInput.addEventListener("change", () => {
        const file = fileInput.files && fileInput.files[0];
        if (!file) return;
        selectedFile = file;
        const nameEl = $("[data-file-name]");
        if (nameEl) nameEl.textContent = `${file.name} · ${formatBytes(file.size)}`;
      });
      fileInput.addEventListener("click", (e) => e.stopPropagation());
    }

    if (els.form) {
      els.form.addEventListener("submit", (e) => {
        e.preventDefault();
        if (activeType === "file") runScan("", "file", selectedFile);
        else runScan(els.input.value.trim(), activeType);
      });
    }

    $$("[data-sample]", root).forEach((btn) => {
      btn.addEventListener("click", () => {
        const type = btn.dataset.type || "hash";
        const q = btn.dataset.query || "";
        setType(type);
        if (els.input) els.input.value = q;
        runScan(q, type);
      });
    });

    $$("[data-new-scan]", root).forEach((btn) =>
      btn.addEventListener("click", () => {
        setType("hash");
        if (els.input) {
          els.input.value = "";
          els.input.focus();
        }
        selectedFile = null;
        const nameEl = $("[data-file-name]");
        if (nameEl) nameEl.textContent = "Henüz dosya seçilmedi";
        const panel = $("[data-scan-result]");
        if (panel) {
          panel.hidden = true;
          panel.classList.remove("is-active");
        }
        currentResult = null;
      })
    );

    const vendorSearch = $("[data-vendor-search]", root);
    const only = $("[data-only-detections]", root);
    if (vendorSearch) vendorSearch.addEventListener("input", filterVendors);
    if (only) only.addEventListener("change", filterVendors);

    const recentBody = $("[data-recent-body]");
    if (recentBody) {
      recentBody.addEventListener("click", (e) => {
        const btn = e.target.closest("[data-rescan]");
        if (!btn) return;
        const scans = readScans();
        const scan = scans[Number(btn.dataset.rescan)];
        if (!scan) return;
        const type = scan.type === "file" ? "hash" : scan.type;
        setType(type);
        if (els.input) els.input.value = scan.query;
        runScan(scan.query, type);
      });
    }

    root.addEventListener("click", async (e) => {
      const copy = e.target.closest("[data-copy-result]");
      if (copy) {
        const text = currentResult ? currentResult.hash || currentResult.query : "";
        if (!text) return;
        try {
          await navigator.clipboard.writeText(text);
          toast("Panoya kopyalandı.", "success");
        } catch (_) {
          toast("Kopyalanamadı.", "error");
        }
      }
      const share = e.target.closest("[data-share-result]");
      if (share && currentResult) {
        const url = `${location.origin}${location.pathname}?q=${encodeURIComponent(currentResult.query)}&type=${encodeURIComponent(currentResult.type)}`;
        try {
          await navigator.clipboard.writeText(url);
          toast("Tarama bağlantısı kopyalandı.", "success");
        } catch (_) {
          toast("Bağlantı kopyalanamadı.", "error");
        }
      }
      const dl = e.target.closest("[data-download-report]");
      if (dl && currentResult) {
        const report = {
          generator: "Vortexis Threat Lab (demo)",
          generatedAt: new Date().toISOString(),
          result: currentResult
        };
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `vortexis-rapor-${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 2000);
        toast("JSON raporu indirildi.", "success");
      }
    });

    renderRecent();

    const params = new URLSearchParams(location.search);
    const q = params.get("q");
    const type = params.get("type");
    if (q) {
      const t = type === "url" ? "url" : "hash";
      setType(t);
      if (els.input) els.input.value = q;
      runScan(q, t);
    } else {
      const sample = buildResult(SAMPLE_HASH, "hash");
      renderResult(sample, true);
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
