# Vortexis Web

Vortexis Windows uygulamasının tanıtım, indirme, destek ve demo tarama sitesi. Statik HTML/CSS/JavaScript ile hazırlanmıştır; GitHub Pages üzerinde yayınlanmaktadır.

- Canlı site: https://vortexisecure.github.io/Vortexisecure/
- Sürümler: https://github.com/vortexisecure/Vortexisecure/releases
- Son sürüm: https://github.com/vortexisecure/Vortexisecure/releases/latest

> **Önemli:** Bu depo bir üretim kimlik doğrulama sistemi veya gerçek bir antivirüs tarama servisi içermez. Giriş/kayıt ve Threat Lab tamamen tarayıcıda çalışan demodur. Ayrıntılar için aşağıdaki bölümlere bakın.

## Sayfalar

| Sayfa | Dosya | Açıklama |
| --- | --- | --- |
| Ana sayfa | `index.html` | Hero, özellikler, ekran görüntüleri, fiyat özeti, SSS |
| Özellikler | `features.html` | Modül ve yetenek detayları |
| Threat Lab | `scanner.html` | Hash / URL / dosya tarama demosu |
| İndir | `download.html` | Sürüm bilgisi, SHA-256, GitHub Releases bağlantısı |
| Planlar | `pricing.html` | Desktop / Pro / Kurumsal planları |
| Destek | `support.html` | SSS, arama, iletişim |
| Giriş | `login.html` | Demo e-posta/parola girişi |
| Kayıt | `register.html` | Demo hesap oluşturma |
| Hesabım | `account.html` | Profil, parola, tarama geçmişi, plan, hesap silme |
| Gizlilik | `privacy.html` | Gizlilik politikası |
| Şartlar | `terms.html` | Kullanım şartları |
| 404 | `404.html` | Bulunamayan sayfa |

## Klasör yapısı

```text
.
├── assets/
│   ├── css/style.css          # Tasarım sistemi ve tüm sayfa stilleri
│   ├── icons.svg              # SVG sembol sprite
│   ├── img/                   # Uygulama ekran görüntüleri ve logo
│   └── js/
│       ├── config.js          # Site, GitHub, sürüm ve demo hesap ayarları
│       ├── app.js             # Tema, menü, arama, sekmeler, formlar
│       ├── auth.js            # Demo kayıt/giriş/hesap işlemleri
│       └── scanner.js         # Threat Lab demo tarayıcısı
├── tools/hash-password.mjs    # Demo parola özeti üretici
├── .github/workflows/pages.yml
├── .nojekyll
├── manifest.webmanifest
├── robots.txt
├── sitemap.xml
└── *.html
```

## Yerel önizleme

Statik site olduğu için herhangi bir sunucu yeterlidir. Proje kökünde:

```powershell
# Python 3
python -m http.server 8080

# veya Node.js
npx serve .
```

Ardından `http://localhost:8080` adresini açın.

> `file://` ile açmak da mümkündür; ancak bazı tarayıcılar `fetch`, `localStorage` veya SVG `<use>` kaynaklarını kısıtlayabilir. Yerel sunucu önerilir.

## Yapılandırma

Site şu depo ve adres için yapılandırıldı:

- Depo: `https://github.com/vortexisecure/Vortexisecure`
- Site: `https://vortexisecure.github.io/Vortexisecure/`

`assets/js/config.js` içindeki `site.url`, `links.github`, `links.releases`, `links.issues` ve `links.download` değerleri bu adrese göre ayarlıdır. Depo adı veya alan adı değişirse:

1. `assets/js/config.js` içindeki ilgili URL'leri güncelleyin.
2. `robots.txt` ve `sitemap.xml` içindeki adresleri güncelleyin.
3. `release` alanındaki sürüm, tarih, boyut ve SHA-256 bilgilerini yeni kurulum dosyasıyla eşleştirin.
4. Demo hesap parolasını değiştirmek istiyorsanız aşağıdaki adımı izleyin.

## Demo hesap ve parola değiştirme

Demo hesabın e-postası `config.js` içinde tanımlıdır. Parola düz metin olarak **saklanmaz**; yalnızca PBKDF2-SHA256 ile türetilmiş özet ve rastgele salt bulunur.

Yeni bir parola için:

```powershell
node tools/hash-password.mjs "yeni-parola"
```

Çıktıdaki `salt`, `hash` ve `iterations` değerlerini `assets/js/config.js` içindeki `demoAccount` alanına yazın. Parolayı Git geçmişine, README'ye veya başka bir dosyaya eklemeyin.

### Demo kimlik doğrulamanın sınırları

- Hesaplar yalnızca `localStorage` içinde tutulur; cihazlar arasında eşitlenmez.
- Parola özeti istemci tarafında doğrulanır. Bu, gerçek bir sunucu tarafı kimlik doğrulama kadar güvenli değildir.
- Tarayıcı verileri temizlendiğinde hesaplar ve oturumlar silinir.
- Gerçek üretim için HTTPS, sunucu tarafı oturum yönetimi, güvenli çerezler, e-posta doğrulama ve parola sıfırlama akışı gerekir.

## Threat Lab demo tarayıcısı

- **Hash:** SHA-256 / SHA-1 / MD5 biçimsel doğrulaması yapılır.
- **URL:** Alan adı normalize edilir; demo sonuç üretilir.
- **Dosya:** Dosyanın SHA-256 özeti tarayıcıda hesaplanır. Dosya hiçbir yere yüklenmez.
- Satıcı tespitleri, risk puanı ve topluluk yorumları **simüle edilir**.
- Son taramalar `localStorage` içinde tutulur; hesap sayfasından temizlenebilir.

Gerçek tarama için bir arka uç servisi ve güvenilir bir tehdit istihbaratı API'si gerekir. Bu demo, ürün arayüzünü göstermek için tasarlanmıştır.

## GitHub Pages ile yayınlama

Site bu depo için GitHub Actions ile yayınlanacak şekilde yapılandırıldı ve ilk dağıtım tamamlandı. Yeni bir değişiklik yayınlamak için:

```powershell
git add .
git commit -m "Site güncellemesi"
git push origin main
```

`.github/workflows/pages.yml` her `main` push'unda siteyi yeniden yayınlar. Dağıtım durumunu **Actions** sekmesinden veya şu komutla kontrol edebilirsiniz:

```powershell
gh run list --repo vortexisecure/Vortexisecure
```

İlk kurulumda **Settings → Pages → Build and deployment → Source** olarak **GitHub Actions** seçilmelidir. Pages henüz etkin değilse API ile de etkinleştirilebilir:

```powershell
gh api -X POST repos/vortexisecure/Vortexisecure/pages -f build_type=workflow
```

### Özel alan adı

GitHub Pages özel alan adı kullanacaksanız depo köküne `CNAME` dosyası ekleyin:

```text
vortexis.example
```

Ayrıca DNS sağlayıcınızda gerekli `A` / `CNAME` kayıtlarını tanımlayın. `config.js`, `robots.txt` ve `sitemap.xml` içindeki adresleri de güncelleyin.

## Kurulum dosyası

`VortexisSetup.exe` bu depoya **dahil edilmez**. GitHub'ın dosya boyutu sınırları ve depo hijyeni nedeniyle kurulum dosyası GitHub Releases üzerinden dağıtılmalıdır.

`download.html` sayfası `data-link="download"` üzerinden `config.js` içindeki `links.download` adresini kullanır. Yeni sürüm yayınlarken:

1. GitHub'da yeni bir Release oluşturun.
2. `VortexisSetup.exe` dosyasını ekleyin.
3. `config.js` içindeki sürüm, boyut ve SHA-256 bilgilerini güncelleyin.
4. `download.html` üzerindeki SHA-256 değerini kontrol edin.

Mevcut sürüm bilgisi:

- Sürüm: `1.0.0` (kararlı)
- İndirme: https://github.com/vortexisecure/Vortexisecure/releases/latest
- Dosya: `VortexisSetup.exe`
- Boyut: `132,6 MB` (`139.090.623` bayt)
- SHA-256: `DE396BF930687390D1393A30DF25D72515F3AC343E1D11F44F61272AFEF022F1`

## Güvenlik notları

- Depoya parola, API anahtarı veya özel anahtar **eklemeyin**.
- Demo hesap parolası yalnızca PBKDF2 salt/hash olarak `config.js` içinde bulunur.
- Formların gerçek bir arka uca bağlanması gerekiyorsa, istemci tarafı doğrulamayı sunucu tarafı doğrulamayla destekleyin.
- Üretimde Content Security Policy (CSP), `Referrer-Policy` ve uygun önbellek başlıkları ekleyin.
- Üçüncü taraf yazı tipi isteklerini azaltmak için fontları kendi sunucunuzda barındırmayı düşünün.

## Test kontrol listesi

- [x] Tüm sayfalar açılıyor ve konsolda hata yok.
- [x] Tema değiştirme kalıcı ve tüm sayfalarda tutarlı.
- [x] Mobil menü açılıp kapanıyor; klavye ile kullanılabiliyor.
- [x] `Ctrl+K` arama paleti çalışıyor.
- [x] Demo kayıt, giriş, çıkış ve hesap silme akışları çalışıyor.
- [x] Profil adı ve parola güncelleme çalışıyor.
- [x] Threat Lab hash, URL ve dosya modları çalışıyor.
- [x] Dosya taramasında dosya seçici tek kez açılıyor.
- [x] Tarama geçmişi hesap sayfasında görünüyor ve temizlenebiliyor.
- [x] JSON rapor indirme ve bağlantı kopyalama çalışıyor.
- [x] `404.html` bilinmeyen yollarda görüntüleniyor.
- [x] `manifest.webmanifest`, `robots.txt` ve `sitemap.xml` erişilebilir.
- [x] GitHub Pages dağıtımı ve `releases/latest` indirme bağlantısı doğrulandı.

## Lisans

Bu depodaki site kodu ve içerik, Vortexis projesine aittir. Açık kaynak olarak paylaşılacaksa uygun bir lisans dosyası (`LICENSE`) ekleyin. Uygulama ikonları, ekran görüntüleri ve marka öğeleri ayrı kullanım koşullarına tabi olabilir.
