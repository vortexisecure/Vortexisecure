/* ==========================================================================
   Vortexis — client-side demo authentication
   --------------------------------------------------------------------------
   Bu dosya statik GitHub Pages demosu içindir. Gerçek üretim ortamında
   kimlik doğrulama mutlaka sunucu tarafında (Supabase, Firebase, Auth0 veya
   kendi API'niz) yapılmalıdır. Parolalar burada düz metin olarak saklanmaz;
   PBKDF2-SHA256 ile türetilmiş özet ve rastgele salt kullanılır.
   ========================================================================== */
(function () {
  "use strict";

  const CFG = window.VORTEXIS || {};
  const AUTH = CFG.auth || {};
  const DEMO = CFG.demoAccount || {};
  const USERS_KEY = AUTH.storageKey || "vortexis.users.v1";
  const SESSION_KEY = AUTH.sessionKey || "vortexis.session.v1";
  const MIN_PASS = AUTH.minPasswordLength || 8;
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  const toast = (msg, type) => {
    if (window.VortexisUI && window.VortexisUI.toast) window.VortexisUI.toast(msg, type);
  };

  const safeParse = (raw, fallback) => {
    try {
      const v = JSON.parse(raw);
      return v == null ? fallback : v;
    } catch (_) {
      return fallback;
    }
  };

  const readUsers = () => {
    try {
      const v = safeParse(localStorage.getItem(USERS_KEY), []);
      return Array.isArray(v) ? v : [];
    } catch (_) {
      return [];
    }
  };

  const writeUsers = (users) => {
    try {
      localStorage.setItem(USERS_KEY, JSON.stringify(users));
    } catch (_) {
      throw new Error("Tarayıcı depolaması kullanılamıyor.");
    }
  };

  const normalizeEmail = (email) => String(email || "").trim().toLowerCase();
  const isEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

  const bytesToB64 = (bytes) => {
    let binary = "";
    bytes.forEach((b) => (binary += String.fromCharCode(b)));
    return btoa(binary);
  };

  const b64ToBytes = (b64) => {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  };

  const randomSalt = () => {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return bytesToB64(bytes);
  };

  const deriveHash = async (password, saltB64, iterations) => {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error("Tarayıcınız güvenli parola işleme özelliğini desteklemiyor. Lütfen güncel bir tarayıcı kullanın.");
    }
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: b64ToBytes(saltB64),
        iterations: Number(iterations) || 120000,
        hash: "SHA-256"
      },
      keyMaterial,
      256
    );
    return bytesToB64(new Uint8Array(bits));
  };

  const constantTimeEqual = (a, b) => {
    a = String(a || "");
    b = String(b || "");
    let diff = a.length ^ b.length;
    const len = Math.max(a.length, b.length);
    for (let i = 0; i < len; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
    return diff === 0;
  };

  const makeId = () =>
    "u_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2, 9);

  /* ---------------------------------------------------------------- seed */
  function seedDemo() {
    if (!DEMO.email || !DEMO.salt || !DEMO.hash) return;
    const users = readUsers();
    const email = normalizeEmail(DEMO.email);
    if (users.some((u) => normalizeEmail(u.email) === email)) return;
    users.push({
      id: makeId(),
      name: DEMO.name || "Vortexis Demo",
      email,
      salt: DEMO.salt,
      hash: DEMO.hash,
      iterations: Number(DEMO.iterations) || 120000,
      plan: "Desktop",
      demo: true,
      createdAt: new Date().toISOString()
    });
    try {
      writeUsers(users);
    } catch (_) {}
  }

  /* ---------------------------------------------------------------- session */
  function saveSession(user, remember) {
    const payload = JSON.stringify({ email: normalizeEmail(user.email), at: Date.now() });
    try {
      if (remember) {
        localStorage.setItem(SESSION_KEY, payload);
        sessionStorage.removeItem(SESSION_KEY);
      } else {
        sessionStorage.setItem(SESSION_KEY, payload);
        localStorage.removeItem(SESSION_KEY);
      }
    } catch (_) {}
  }

  function getSession() {
    let raw = null;
    try {
      raw = localStorage.getItem(SESSION_KEY) || sessionStorage.getItem(SESSION_KEY);
    } catch (_) {
      return null;
    }
    if (!raw) return null;
    const session = safeParse(raw, null);
    if (!session || !session.email) return null;
    const user = readUsers().find((u) => normalizeEmail(u.email) === normalizeEmail(session.email));
    return user ? { session, user } : null;
  }

  function currentUser() {
    const s = getSession();
    return s ? s.user : null;
  }

  function logout(redirect) {
    try {
      localStorage.removeItem(SESSION_KEY);
      sessionStorage.removeItem(SESSION_KEY);
    } catch (_) {}
    if (redirect !== false) window.location.href = "index.html";
  }

  /* ---------------------------------------------------------------- auth */
  async function register({ name, email, password }) {
    name = String(name || "").trim();
    email = normalizeEmail(email);
    password = String(password || "");

    if (name.length < 2) throw new Error("Adınız en az 2 karakter olmalı.");
    if (!isEmail(email)) throw new Error("Geçerli bir e-posta adresi girin.");
    if (password.length < MIN_PASS) throw new Error(`Parola en az ${MIN_PASS} karakter olmalı.`);

    const users = readUsers();
    if (users.some((u) => normalizeEmail(u.email) === email)) {
      throw new Error("Bu e-posta ile bir hesap zaten var. Giriş yapmayı deneyin.");
    }

    const salt = randomSalt();
    const hash = await deriveHash(password, salt, 120000);
    const user = {
      id: makeId(),
      name,
      email,
      salt,
      hash,
      iterations: 120000,
      plan: "Desktop",
      demo: false,
      createdAt: new Date().toISOString()
    };
    users.push(user);
    writeUsers(users);
    saveSession(user, true);
    return user;
  }

  async function login(email, password, remember) {
    email = normalizeEmail(email);
    password = String(password || "");
    if (!isEmail(email)) throw new Error("Geçerli bir e-posta adresi girin.");
    if (!password) throw new Error("Parolanızı girin.");

    const user = readUsers().find((u) => normalizeEmail(u.email) === email);
    if (!user) throw new Error("Bu e-posta ile kayıtlı bir hesap bulunamadı.");

    const hash = await deriveHash(password, user.salt, user.iterations || 120000);
    if (!constantTimeEqual(hash, user.hash)) throw new Error("Parola hatalı. Tekrar deneyin.");

    saveSession(user, remember !== false);
    return user;
  }

  async function changePassword(current, next) {
    const s = getSession();
    if (!s) throw new Error("Oturum bulunamadı. Tekrar giriş yapın.");
    if (!current) throw new Error("Mevcut parolanızı girin.");
    if (!next || next.length < MIN_PASS) throw new Error(`Yeni parola en az ${MIN_PASS} karakter olmalı.`);

    const users = readUsers();
    const idx = users.findIndex((u) => normalizeEmail(u.email) === normalizeEmail(s.user.email));
    if (idx < 0) throw new Error("Hesap bulunamadı.");

    const currentHash = await deriveHash(current, users[idx].salt, users[idx].iterations || 120000);
    if (!constantTimeEqual(currentHash, users[idx].hash)) throw new Error("Mevcut parola hatalı.");

    const salt = randomSalt();
    const hash = await deriveHash(next, salt, 120000);
    users[idx] = { ...users[idx], salt, hash, iterations: 120000 };
    writeUsers(users);
    saveSession(users[idx], true);
    return users[idx];
  }

  function updateProfile(name) {
    name = String(name || "").trim();
    if (name.length < 2) throw new Error("Adınız en az 2 karakter olmalı.");
    const s = getSession();
    if (!s) throw new Error("Oturum bulunamadı.");
    const users = readUsers();
    const idx = users.findIndex((u) => normalizeEmail(u.email) === normalizeEmail(s.user.email));
    if (idx < 0) throw new Error("Hesap bulunamadı.");
    users[idx].name = name;
    writeUsers(users);
    saveSession(users[idx], true);
    return users[idx];
  }

  function deleteAccount() {
    const s = getSession();
    if (!s) return;
    if (s.user.demo) throw new Error("Demo hesabı silinemez. Kendi hesabınızı oluşturarak devam edebilirsiniz.");
    const users = readUsers().filter((u) => normalizeEmail(u.email) !== normalizeEmail(s.user.email));
    writeUsers(users);
    logout(false);
  }

  /* ---------------------------------------------------------------- UI */
  function initials(name) {
    const parts = String(name || "V").trim().split(/\s+/).filter(Boolean);
    return parts
      .slice(0, 2)
      .map((p) => p[0].toLocaleUpperCase("tr-TR"))
      .join("") || "V";
  }

  function refreshNav() {
    const s = getSession();
    $$("[data-auth='guest']").forEach((el) => (el.hidden = !!s));
    $$("[data-auth='user']").forEach((el) => (el.hidden = !s));
    if (!s) return;
    $$("[data-auth-name]").forEach((el) => (el.textContent = s.user.name));
    $$("[data-auth-email]").forEach((el) => (el.textContent = s.user.email));
    $$("[data-auth-initials]").forEach((el) => (el.textContent = initials(s.user.name)));
    $$("[data-auth-plan]").forEach((el) => (el.textContent = s.user.plan || "Desktop"));
  }

  function showError(el, message) {
    if (!el) return;
    el.textContent = message;
    el.classList.add("is-visible");
    el.hidden = false;
  }

  function clearError(el) {
    if (!el) return;
    el.textContent = "";
    el.classList.remove("is-visible");
    el.hidden = true;
  }

  function setLoading(btn, loading, label) {
    if (!btn) return;
    if (loading) {
      btn.dataset.original = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = `<span class="spinner" aria-hidden="true"></span>${label || "İşleniyor…"}`;
    } else {
      btn.disabled = false;
      if (btn.dataset.original) btn.innerHTML = btn.dataset.original;
    }
  }

  function initPasswordStrength() {
    $$("[data-strength]").forEach((meter) => {
      const input = $(meter.dataset.strength);
      if (!input) return;
      const bars = $$(".strength-bar", meter);
      const label = $("[data-strength-label]", meter);
      const update = () => {
        const v = input.value;
        let score = 0;
        if (v.length >= MIN_PASS) score++;
        if (v.length >= 12) score++;
        if (/[a-z]/.test(v) && /[A-Z]/.test(v)) score++;
        if (/\d/.test(v)) score++;
        if (/[^A-Za-z0-9]/.test(v)) score++;
        score = Math.min(4, score);
        bars.forEach((b, i) => b.classList.toggle("is-on", i < score));
        meter.dataset.score = String(score);
        if (label) {
          label.textContent = !v
            ? "En az 8 karakter"
            : ["Çok zayıf", "Zayıf", "Orta", "Güçlü", "Çok güçlü"][score] || "Çok güçlü";
        }
      };
      input.addEventListener("input", update);
      update();
    });
  }

  function initLogin() {
    const form = $("[data-auth-form='login']");
    if (!form) return;
    const error = $("[data-auth-error]", form);
    const btn = $("button[type=submit]", form);
    const email = $("input[name=email]", form);
    const password = $("input[name=password]", form);
    const remember = $("input[name=remember]", form);

    const fillDemo = $("[data-fill-demo]");
    if (fillDemo) {
      fillDemo.addEventListener("click", () => {
        if (email) email.value = DEMO.email || "";
        if (password) password.focus();
        toast("Demo e-posta dolduruldu. Daha önce verdiğiniz uygulama şifresini girin.", "info");
      });
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      clearError(error);
      setLoading(btn, true, "Giriş yapılıyor…");
      try {
        await login(email.value, password.value, remember ? remember.checked : true);
        const params = new URLSearchParams(location.search);
        const next = params.get("next");
        const safeNext = next && /^[a-z0-9._-]+\.html$/i.test(next) ? next : "account.html";
        window.location.href = safeNext;
      } catch (err) {
        showError(error, err.message || "Giriş yapılamadı.");
        setLoading(btn, false);
      }
    });
  }

  function initRegister() {
    const form = $("[data-auth-form='register']");
    if (!form) return;
    const error = $("[data-auth-error]", form);
    const btn = $("button[type=submit]", form);
    const name = $("input[name=name]", form);
    const email = $("input[name=email]", form);
    const password = $("input[name=password]", form);
    const confirm = $("input[name=confirm]", form);
    const terms = $("input[name=terms]", form);

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      clearError(error);
      if (password.value !== confirm.value) {
        showError(error, "Parolalar birbiriyle eşleşmiyor.");
        confirm.focus();
        return;
      }
      if (terms && !terms.checked) {
        showError(error, "Devam etmek için kullanım şartlarını kabul edin.");
        return;
      }
      setLoading(btn, true, "Hesap oluşturuluyor…");
      try {
        await register({ name: name.value, email: email.value, password: password.value });
        window.location.href = "account.html";
      } catch (err) {
        showError(error, err.message || "Kayıt tamamlanamadı.");
        setLoading(btn, false);
      }
    });
  }

  function fmtDate(value, withTime) {
    try {
      const d = new Date(value);
      return d.toLocaleDateString("tr-TR", {
        day: "2-digit",
        month: "long",
        year: "numeric",
        ...(withTime ? { hour: "2-digit", minute: "2-digit" } : {})
      });
    } catch (_) {
      return "—";
    }
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function initAccount() {
    if (!document.body.hasAttribute("data-account-page")) return;
    const s = getSession();
    if (!s) {
      window.location.href = "login.html?next=account.html";
      return;
    }
    const user = s.user;
    $$("[data-account-name]").forEach((el) => (el.textContent = user.name));
    $$("[data-account-email]").forEach((el) => (el.textContent = user.email));
    $$("[data-account-initials]").forEach((el) => (el.textContent = initials(user.name)));
    $$("[data-account-plan]").forEach((el) => (el.textContent = user.plan || "Desktop"));
    $$("[data-account-since]").forEach((el) => (el.textContent = fmtDate(user.createdAt)));
    $$("[data-account-id]").forEach((el) => (el.textContent = user.id.slice(-8).toUpperCase()));
    $$("[data-account-demo]").forEach((el) => (el.hidden = !user.demo));

    const nameInput = $("[data-profile-form] input[name=name]");
    if (nameInput) nameInput.value = user.name;
    const emailInput = $("[data-profile-email]");
    if (emailInput) emailInput.value = user.email;

    const deleteBtn = $("[data-delete-account]");
    if (deleteBtn && user.demo) {
      deleteBtn.disabled = true;
      deleteBtn.title = "Demo hesabı silinemez";
    }

    const renderScans = () => {
      const scans = safeParse(localStorage.getItem((CFG.scanner && CFG.scanner.storageKey) || "vortexis.scans.v1"), []);
      const list = Array.isArray(scans) ? scans : [];
      const body = $("[data-account-scans]");
      const empty = $("[data-account-scans-empty]");
      $$("[data-stat-scans]").forEach((el) => (el.textContent = list.length));
      $$("[data-stat-clean]").forEach((el) => (el.textContent = list.filter((x) => x.verdict === "clean").length));
      $$("[data-stat-threats]").forEach(
        (el) => (el.textContent = list.filter((x) => x.verdict === "malicious" || x.verdict === "suspicious").length)
      );
      if (!body) return;
      if (!list.length) {
        body.innerHTML = "";
        if (empty) empty.hidden = false;
        return;
      }
      if (empty) empty.hidden = true;
      body.innerHTML = list
        .slice(0, 6)
        .map(
          (x) => `<tr>
            <td><span class="scan-type-icon">${escapeHtml((x.type || "hash").toUpperCase())}</span><span class="scan-query">${escapeHtml(x.name || x.query || "—")}</span></td>
            <td><span class="verdict-dot verdict-dot--${escapeHtml(x.verdict || "clean")}"></span>${escapeHtml(
              x.verdict === "malicious" ? "Zararlı" : x.verdict === "suspicious" ? "Şüpheli" : "Temiz"
            )}</td>
            <td>${escapeHtml(String(x.detections ?? 0))}/${escapeHtml(String(x.total ?? 0))}</td>
            <td>${escapeHtml(fmtDate(x.time, true))}</td>
          </tr>`
        )
        .join("");
    };
    renderScans();

    const clearScans = $("[data-clear-scans]");
    if (clearScans) {
      clearScans.addEventListener("click", () => {
        if (!window.confirm("Tarama geçmişini temizlemek istiyor musunuz?")) return;
        try {
          localStorage.removeItem((CFG.scanner && CFG.scanner.storageKey) || "vortexis.scans.v1");
        } catch (_) {}
        renderScans();
        toast("Tarama geçmişi temizlendi.", "success");
      });
    }

    const profileForm = $("[data-profile-form]");
    if (profileForm) {
      profileForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const error = $("[data-auth-error]", profileForm);
        clearError(error);
        try {
          const updated = updateProfile(nameInput.value);
          toast("Profil güncellendi.", "success");
          refreshNav();
          $$("[data-account-name]").forEach((el) => (el.textContent = updated.name));
          $$("[data-account-initials]").forEach((el) => (el.textContent = initials(updated.name)));
        } catch (err) {
          showError(error, err.message);
        }
      });
    }

    const passForm = $("[data-password-form]");
    if (passForm) {
      passForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const error = $("[data-auth-error]", passForm);
        clearError(error);
        const current = $("input[name=current]", passForm);
        const next = $("input[name=new]", passForm);
        const confirm = $("input[name=confirm]", passForm);
        if (next.value !== confirm.value) {
          showError(error, "Yeni parolalar eşleşmiyor.");
          return;
        }
        const btn = $("button[type=submit]", passForm);
        setLoading(btn, true, "Güncelleniyor…");
        try {
          await changePassword(current.value, next.value);
          passForm.reset();
          toast("Parolanız güncellendi.", "success");
        } catch (err) {
          showError(error, err.message);
        } finally {
          setLoading(btn, false);
        }
      });
    }

    $$("[data-logout]").forEach((btn) =>
      btn.addEventListener("click", () => {
        logout();
      })
    );

    if (deleteBtn && !user.demo) {
      deleteBtn.addEventListener("click", () => {
        if (!window.confirm("Hesabınızı kalıcı olarak silmek istediğinize emin misiniz? Bu işlem geri alınamaz.")) return;
        try {
          deleteAccount();
          window.location.href = "index.html";
        } catch (err) {
          toast(err.message, "error");
        }
      });
    }

    $$("[data-copy-email]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(user.email);
          toast("E-posta panoya kopyalandı.", "success");
        } catch (_) {}
      });
    });
  }

  function initAuthPages() {
    if (!document.body.hasAttribute("data-auth-page")) return;
    const s = getSession();
    if (s && !new URLSearchParams(location.search).has("next")) {
      window.location.href = "account.html";
      return;
    }
    initPasswordStrength();
    initLogin();
    initRegister();
  }

  /* ---------------------------------------------------------------- boot */
  seedDemo();

  document.addEventListener("DOMContentLoaded", () => {
    refreshNav();
    initAuthPages();
    initAccount();
    $$("[data-logout]").forEach((btn) => {
      if (!document.body.hasAttribute("data-account-page")) {
        btn.addEventListener("click", () => logout());
      }
    });
  });

  window.VortexisAuth = {
    register,
    login,
    logout,
    currentUser,
    getSession,
    refreshNav,
    changePassword,
    updateProfile,
    deleteAccount,
    deriveHash
  };
})();
