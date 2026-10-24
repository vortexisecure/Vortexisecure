/* ==========================================================================
   Vortexis site configuration
   --------------------------------------------------------------------------
   Bu dosya sitenin tek ayar noktasıdır. GitHub'a yüklemeden önce aşağıdaki
   alanları kendi hesabınıza göre güncelleyin.
   ========================================================================== */
window.VORTEXIS = {
  site: {
    name: "Vortexis",
    tagline: "Sistem bakımı, yeniden düşünüldü.",
    // GitHub Pages adresi. Sitemap ve paylaşım bağlantıları için kullanılır.
    url: "https://vortexisecure.github.io/Vortexisecure",
    locale: "tr_TR"
  },

  links: {
    // GitHub deposu ve sürüm bağlantıları.
    github: "https://github.com/vortexisecure/Vortexisecure",
    releases: "https://github.com/vortexisecure/Vortexisecure/releases",
    issues: "https://github.com/vortexisecure/Vortexisecure/issues",
    download: "https://github.com/vortexisecure/Vortexisecure/releases/latest"
  },

  release: {
    version: "1.0.0",
    channel: "Kararlı",
    date: "2026-10-24",
    size: "132,6 MB",
    fileName: "VortexisSetup.exe",
    sha256: "DE396BF930687390D1393A30DF25D72515F3AC343E1D11F44F61272AFEF022F1",
    minWindows: "Windows 10 21H2 / Windows 11",
    architecture: "x64"
  },

  /*
   * Demo hesabı.
   * E-posta: daha önce verilen yerleşik gönderici adresi.
   * Parola: daha önce verilen uygulama şifresi.
   *
   * Parola burada DÜZ METİN olarak tutulmaz. Yalnızca PBKDF2-SHA256
   * türetilmiş özet ve rastgele salt bulunur. Yeni bir parola için:
   *   node tools/hash-password.mjs "yeni-parola"
   * komutunu çalıştırıp salt/hash değerlerini buraya yazın.
   */
  demoAccount: {
    email: "vortexisecure@gmail.com",
    name: "Vortexis Demo",
    salt: "X/MPkp0krJPy8Bd5wUcRsg==",
    hash: "GwF5fv++R6ROCGun3VrSW30gJ/2H68tCQHZ51Y9iWTw=",
    iterations: 120000
  },

  auth: {
    storageKey: "vortexis.users.v1",
    sessionKey: "vortexis.session.v1",
    minPasswordLength: 8
  },

  scanner: {
    storageKey: "vortexis.scans.v1",
    maxRecent: 8,
    maxFileSize: 104857600 // 100 MB
  }
};
