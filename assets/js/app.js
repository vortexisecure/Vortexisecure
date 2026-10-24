/* ==========================================================================
   Vortexis — shared UI behaviour
   ========================================================================== */
(function () {
  "use strict";

  const CFG = window.VORTEXIS || {};
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const icon = (name, cls) =>
    `<svg class="icon ${cls || ""}" aria-hidden="true"><use href="assets/icons.svg#${name}"></use></svg>`;

  /* ---------------------------------------------------------------- toasts */
  function ensureToastStack() {
    let stack = $(".toast-stack");
    if (!stack) {
      stack = document.createElement("div");
      stack.className = "toast-stack";
      stack.setAttribute("aria-live", "polite");
      document.body.appendChild(stack);
    }
    return stack;
  }

  function toast(message, type = "info") {
    const stack = ensureToastStack();
    const el = document.createElement("div");
    el.className = `toast toast--${type}`;
    el.innerHTML = `${icon(type === "success" ? "check-circle" : type === "error" ? "alert-triangle" : "info")}<span>${message}</span>`;
    stack.appendChild(el);
    requestAnimationFrame(() => el.classList.add("is-visible"));
    window.setTimeout(() => {
      el.classList.remove("is-visible");
      window.setTimeout(() => el.remove(), 250);
    }, 3600);
  }

  window.VortexisUI = { toast, icon };

  /* ---------------------------------------------------------------- theme */
  function currentTheme() {
    return document.documentElement.getAttribute("data-theme") || "dark";
  }

  function setTheme(theme, announce) {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("vortexis.theme", theme);
    } catch (_) {}

    $$("[data-theme-toggle]").forEach((btn) => {
      const isDark = theme === "dark";
      btn.setAttribute("aria-label", isDark ? "Açık temaya geç" : "Koyu temaya geç");
      btn.setAttribute("title", isDark ? "Açık tema" : "Koyu tema");
      const use = $("use", btn);
      if (use) {
        const name = isDark ? "sun" : "moon";
        use.setAttribute("href", `assets/icons.svg#${name}`);
        use.setAttributeNS("http://www.w3.org/1999/xlink", "xlink:href", `assets/icons.svg#${name}`);
      }
    });

    $$("img[data-light-src][data-dark-src]").forEach((img) => {
      img.src = theme === "light" ? img.dataset.lightSrc : img.dataset.darkSrc;
    });

    if (announce) toast(theme === "dark" ? "Koyu tema etkin." : "Açık tema etkin.", "info");
  }

  function initTheme() {
    const stored = (() => {
      try {
        return localStorage.getItem("vortexis.theme");
      } catch (_) {
        return null;
      }
    })();
    setTheme(stored === "light" ? "light" : "dark", false);
    $$("[data-theme-toggle]").forEach((btn) =>
      btn.addEventListener("click", () => setTheme(currentTheme() === "dark" ? "light" : "dark", true))
    );
  }

  /* ---------------------------------------------------------------- header */
  function initHeader() {
    const header = $(".site-header");
    if (header) {
      const onScroll = () => header.classList.toggle("is-scrolled", window.scrollY > 10);
      onScroll();
      window.addEventListener("scroll", onScroll, { passive: true });
    }

    const page = document.body.dataset.page;
    if (page) {
      $$("[data-nav]").forEach((link) => {
        const active = link.dataset.nav === page;
        link.classList.toggle("is-active", active);
        if (active) link.setAttribute("aria-current", "page");
      });
    }

    const toggle = $("[data-menu-toggle]");
    const menu = $("#mobile-menu");
    if (toggle && menu) {
      const close = () => {
        menu.classList.remove("is-open");
        toggle.setAttribute("aria-expanded", "false");
        document.body.classList.remove("menu-open");
        const use = $("use", toggle);
        if (use) {
          use.setAttribute("href", "assets/icons.svg#menu");
          use.setAttributeNS("http://www.w3.org/1999/xlink", "xlink:href", "assets/icons.svg#menu");
        }
      };
      const open = () => {
        menu.classList.add("is-open");
        toggle.setAttribute("aria-expanded", "true");
        document.body.classList.add("menu-open");
        const use = $("use", toggle);
        if (use) {
          use.setAttribute("href", "assets/icons.svg#x");
          use.setAttributeNS("http://www.w3.org/1999/xlink", "xlink:href", "assets/icons.svg#x");
        }
      };
      toggle.addEventListener("click", () => (menu.classList.contains("is-open") ? close() : open()));
      $$("a", menu).forEach((a) => a.addEventListener("click", close));
      document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") close();
      });
      window.addEventListener("resize", () => {
        if (window.innerWidth > 900) close();
      });
    }
  }

  /* ---------------------------------------------------------------- search */
  const SEARCH_ITEMS = [
    { title: "Ana Sayfa", desc: "Vortexis'e genel bakış", href: "index.html", icon: "layers", keys: "home ana sayfa" },
    { title: "Özellikler", desc: "Tüm modüller ve yetenekler", href: "features.html", icon: "sparkles", keys: "features özellikler modül" },
    { title: "Threat Lab", desc: "Hash, URL ve dosya ön incelemesi", href: "scanner.html", icon: "scan", keys: "scanner tarama virüs threat lab hash url" },
    { title: "İndir", desc: "Windows kurulum dosyası", href: "download.html", icon: "download", keys: "download indir setup exe windows" },
    { title: "Planlar", desc: "Desktop, Pro ve Kurumsal", href: "pricing.html", icon: "layers", keys: "pricing plan fiyat ücretsiz pro" },
    { title: "Destek", desc: "SSS, kurulum ve iletişim", href: "support.html", icon: "message-circle", keys: "support destek yardım sss iletişim" },
    { title: "Hesabım", desc: "Profil ve tarama geçmişi", href: "account.html", icon: "user", keys: "account hesap profil" },
    { title: "Giriş yap", desc: "Mevcut hesabınıza giriş", href: "login.html", icon: "key", keys: "login giriş" },
    { title: "Kayıt ol", desc: "Yeni bir Vortexis hesabı", href: "register.html", icon: "user", keys: "register kayıt ol" }
  ];

  function initSearch() {
    if ($(".search-overlay")) return;
    const overlay = document.createElement("div");
    overlay.className = "search-overlay";
    overlay.innerHTML = `
      <div class="search-dialog" role="dialog" aria-modal="true" aria-label="Sitede ara">
        <div class="search-input-row">
          ${icon("search")}
          <input type="search" class="search-input" placeholder="Sayfa, özellik veya araç ara…" autocomplete="off" aria-label="Arama">
          <kbd>ESC</kbd>
        </div>
        <div class="search-results"></div>
        <div class="search-footer"><span>${icon("command")} ile aç</span><span>↑ ↓ gez · Enter aç</span></div>
      </div>`;
    document.body.appendChild(overlay);

    const input = $(".search-input", overlay);
    const results = $(".search-results", overlay);
    let filtered = SEARCH_ITEMS.slice();
    let active = 0;

    const render = () => {
      results.innerHTML = filtered.length
        ? filtered
            .map(
              (item, i) => `
          <a class="search-result ${i === active ? "is-active" : ""}" href="${item.href}">
            <span class="search-result-icon">${icon(item.icon)}</span>
            <span><strong>${item.title}</strong><small>${item.desc}</small></span>
            ${icon("chevron-right", "search-result-arrow")}
          </a>`
            )
            .join("")
        : `<div class="search-empty">${icon("search")}<p>Sonuç bulunamadı.</p><small>Farklı bir kelime deneyin.</small></div>`;
    };

    const filter = () => {
      const q = input.value.trim().toLowerCase();
      filtered = SEARCH_ITEMS.filter((item) => !q || `${item.title} ${item.desc} ${item.keys}`.toLowerCase().includes(q));
      active = 0;
      render();
    };

    const open = () => {
      overlay.classList.add("is-open");
      document.body.classList.add("search-open");
      input.value = "";
      filter();
      window.setTimeout(() => input.focus(), 30);
    };
    const close = () => {
      overlay.classList.remove("is-open");
      document.body.classList.remove("search-open");
    };

    $$("[data-search-open]").forEach((btn) => btn.addEventListener("click", open));
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) close();
    });
    input.addEventListener("input", filter);
    input.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        active = Math.min(active + 1, filtered.length - 1);
        render();
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        active = Math.max(active - 1, 0);
        render();
      } else if (e.key === "Enter" && filtered[active]) {
        window.location.href = filtered[active].href;
      }
    });

    document.addEventListener("keydown", (e) => {
      const tag = (e.target.tagName || "").toLowerCase();
      const typing = tag === "input" || tag === "textarea" || tag === "select" || e.target.isContentEditable;
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        overlay.classList.contains("is-open") ? close() : open();
      } else if (e.key === "/" && !typing && !overlay.classList.contains("is-open")) {
        e.preventDefault();
        open();
      } else if (e.key === "Escape" && overlay.classList.contains("is-open")) {
        close();
      }
    });

    render();
  }

  /* ---------------------------------------------------------------- tabs */
  function initTabs() {
    $$("[data-tabs]").forEach((group) => {
      const buttons = $$("[data-tab]", group);
      const panels = $$("[data-panel]", group);
      const activate = (name) => {
        buttons.forEach((b) => {
          const on = b.dataset.tab === name;
          b.classList.toggle("is-active", on);
          b.setAttribute("aria-selected", on ? "true" : "false");
          b.tabIndex = on ? 0 : -1;
        });
        panels.forEach((p) => {
          const on = p.dataset.panel === name;
          p.classList.toggle("is-active", on);
          p.hidden = !on;
        });
      };
      buttons.forEach((btn) => {
        btn.addEventListener("click", () => activate(btn.dataset.tab));
        btn.addEventListener("keydown", (e) => {
          const i = buttons.indexOf(btn);
          if (e.key === "ArrowRight" || e.key === "ArrowDown") {
            e.preventDefault();
            buttons[(i + 1) % buttons.length].focus();
            buttons[(i + 1) % buttons.length].click();
          }
          if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
            e.preventDefault();
            buttons[(i - 1 + buttons.length) % buttons.length].focus();
            buttons[(i - 1 + buttons.length) % buttons.length].click();
          }
        });
      });
      if (buttons[0]) activate(buttons[0].dataset.tab);
    });
  }

  /* ---------------------------------------------------------------- accordions */
  function initAccordions() {
    $$("[data-accordion]").forEach((btn) => {
      const panel = btn.nextElementSibling;
      if (!panel) return;
      const set = (open) => {
        btn.setAttribute("aria-expanded", open ? "true" : "false");
        panel.hidden = !open;
        panel.classList.toggle("is-open", open);
      };
      set(btn.getAttribute("aria-expanded") === "true");
      btn.addEventListener("click", () => set(btn.getAttribute("aria-expanded") !== "true"));
    });
  }

  /* ---------------------------------------------------------------- copy */
  function initCopy() {
    $$("[data-copy]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        let text = btn.dataset.copy || "";
        if (btn.dataset.copyTarget) {
          const target = $(btn.dataset.copyTarget);
          text = target ? (target.value || target.textContent || "").trim() : "";
        }
        if (!text) return;
        try {
          await navigator.clipboard.writeText(text);
          toast("Panoya kopyalandı.", "success");
        } catch (_) {
          const ta = document.createElement("textarea");
          ta.value = text;
          document.body.appendChild(ta);
          ta.select();
          try {
            document.execCommand("copy");
            toast("Panoya kopyalandı.", "success");
          } catch (__) {
            toast("Kopyalanamadı.", "error");
          }
          ta.remove();
        }
      });
    });
  }

  /* ---------------------------------------------------------------- counters */
  function initCounters() {
    const nodes = $$("[data-count]");
    if (!nodes.length) return;
    const animate = (el) => {
      const target = Number(el.dataset.count || 0);
      const suffix = el.dataset.suffix || "";
      const prefix = el.dataset.prefix || "";
      const decimals = Number(el.dataset.decimals || 0);
      const duration = prefersReduced ? 0 : 1100;
      const start = performance.now();
      const fmt = (n) =>
        n.toLocaleString("tr-TR", { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
      const tick = (now) => {
        const p = duration === 0 ? 1 : Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - p, 3);
        el.textContent = prefix + fmt(target * eased) + suffix;
        if (p < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    };
    if (prefersReduced || !("IntersectionObserver" in window)) {
      nodes.forEach(animate);
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            animate(entry.target);
            io.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.35 }
    );
    nodes.forEach((n) => io.observe(n));
  }

  /* ---------------------------------------------------------------- reveal */
  function initReveal() {
    const nodes = $$(".reveal");
    if (!nodes.length) return;
    if (prefersReduced || !("IntersectionObserver" in window)) {
      nodes.forEach((n) => n.classList.add("in-view"));
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("in-view");
            io.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.12, rootMargin: "0px 0px -40px 0px" }
    );
    nodes.forEach((n) => io.observe(n));
    // Emniyet kemeri: observer herhangi bir nedenle çalışmazsa içerik görünür kalsın.
    window.setTimeout(() => nodes.forEach((n) => n.classList.add("in-view")), 3000);
  }

  /* ---------------------------------------------------------------- forms */
  function initNewsletter() {
    $$("[data-newsletter]").forEach((form) => {
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        const input = $("input[type=email]", form);
        const email = input ? input.value.trim() : "";
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          toast("Geçerli bir e-posta girin.", "error");
          if (input) input.focus();
          return;
        }
        try {
          const list = JSON.parse(localStorage.getItem("vortexis.newsletter") || "[]");
          if (!list.includes(email)) list.push(email);
          localStorage.setItem("vortexis.newsletter", JSON.stringify(list));
        } catch (_) {}
        form.reset();
        toast("Kaydınız alındı. Teşekkürler!", "success");
      });
    });
  }

  function initContact() {
    $$("[data-contact-form]").forEach((form) => {
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        const data = Object.fromEntries(new FormData(form).entries());
        if (!data.name || !data.email || !data.message) {
          toast("Lütfen zorunlu alanları doldurun.", "error");
          return;
        }
        try {
          const list = JSON.parse(localStorage.getItem("vortexis.messages") || "[]");
          list.push({ ...data, at: new Date().toISOString() });
          localStorage.setItem("vortexis.messages", JSON.stringify(list));
        } catch (_) {}
        form.reset();
        toast("Mesajınız alındı. En kısa sürede dönüş yapacağız.", "success");
      });
    });
  }

  function initFaqSearch() {
    $$("[data-faq-search]").forEach((input) => {
      const scope = $(input.dataset.faqScope || "body");
      if (!scope) return;
      const items = $$("[data-faq-item]", scope);
      const empty = $("[data-faq-empty]", scope);
      input.addEventListener("input", () => {
        const q = input.value.trim().toLowerCase();
        let shown = 0;
        items.forEach((item) => {
          const on = !q || item.textContent.toLowerCase().includes(q);
          item.hidden = !on;
          if (on) shown++;
        });
        if (empty) empty.hidden = shown !== 0;
      });
    });
  }

  function initMiniScan() {
    $$("[data-mini-scan]").forEach((form) => {
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        const input = $("input", form);
        const q = input ? input.value.trim() : "";
        if (!q) {
          toast("Bir hash, URL veya dosya adı girin.", "error");
          if (input) input.focus();
          return;
        }
        window.location.href = `scanner.html?q=${encodeURIComponent(q)}&type=hash`;
      });
    });
  }

  function initPasswordToggles() {
    $$("[data-password-toggle]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const input = $(btn.dataset.target);
        if (!input) return;
        const show = input.type === "password";
        input.type = show ? "text" : "password";
        btn.setAttribute("aria-label", show ? "Parolayı gizle" : "Parolayı göster");
        const use = $("use", btn);
        if (use) {
          const name = show ? "eye-off" : "eye";
          use.setAttribute("href", `assets/icons.svg#${name}`);
          use.setAttributeNS("http://www.w3.org/1999/xlink", "xlink:href", `assets/icons.svg#${name}`);
        }
      });
    });
  }

  /* ---------------------------------------------------------------- config */
  function initConfig() {
    if (!CFG.links) return;
    const map = {
      github: CFG.links.github,
      releases: CFG.links.releases,
      issues: CFG.links.issues,
      download: CFG.links.download
    };
    Object.entries(map).forEach(([key, url]) => {
      if (!url) return;
      $$(`[data-link="${key}"]`).forEach((el) => {
        el.setAttribute("href", url);
      });
    });

    if (CFG.release) {
      const r = CFG.release;
      $$("[data-release-version]").forEach((el) => (el.textContent = `v${r.version}`));
      $$("[data-release-size]").forEach((el) => (el.textContent = r.size));
      $$("[data-release-date]").forEach((el) => (el.textContent = r.date));
      $$("[data-release-file]").forEach((el) => (el.textContent = r.fileName));
      $$("[data-release-sha]").forEach((el) => (el.textContent = r.sha256));
      $$("[data-release-channel]").forEach((el) => (el.textContent = r.channel));
      $$("[data-release-os]").forEach((el) => (el.textContent = r.minWindows));
      $$("[data-release-arch]").forEach((el) => (el.textContent = r.architecture));
    }
  }

  /* ---------------------------------------------------------------- misc */
  function initMisc() {
    $$("[data-year]").forEach((el) => (el.textContent = new Date().getFullYear()));

    $$("[data-external]").forEach((el) => {
      el.setAttribute("target", "_blank");
      el.setAttribute("rel", "noopener noreferrer");
    });

    if (!$(".to-top")) {
      const btn = document.createElement("button");
      btn.className = "to-top";
      btn.setAttribute("aria-label", "Yukarı çık");
      btn.innerHTML = icon("chevron-down");
      btn.addEventListener("click", () => window.scrollTo({ top: 0, behavior: prefersReduced ? "auto" : "smooth" }));
      document.body.appendChild(btn);
      const onScroll = () => btn.classList.toggle("is-visible", window.scrollY > 600);
      onScroll();
      window.addEventListener("scroll", onScroll, { passive: true });
    }

    document.body.classList.add("page-ready");
  }

  /* ---------------------------------------------------------------- boot */
  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    initHeader();
    initSearch();
    initTabs();
    initAccordions();
    initCopy();
    initCounters();
    initReveal();
    initNewsletter();
    initContact();
    initFaqSearch();
    initMiniScan();
    initPasswordToggles();
    initConfig();
    initMisc();
    if (window.VortexisAuth && typeof window.VortexisAuth.refreshNav === "function") {
      window.VortexisAuth.refreshNav();
    }
  });
})();
