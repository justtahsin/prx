# prx

[![CI](https://github.com/justtahsin/prx/actions/workflows/ci.yml/badge.svg)](https://github.com/justtahsin/prx/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/justtahsin/prx)](https://github.com/justtahsin/prx/releases/latest)
[![license](https://img.shields.io/github/license/justtahsin/prx)](LICENSE)

Xray/V2Ray sınıfı bir proxy sistemi — ama kurulumu iki komut, bağlanması tek
link. Sunucu ve istemci tek dosyalık statik Go ikilileri; başka hiçbir şey
kurmanız gerekmiyor.

```
sunucuda:   prxd init && prxd install      # yapılandır, servise al, başlat
            prxd user add ali              # kullanıcı ekle → link + QR basar

istemcide:  prx 'prx://...'                # SOCKS5 :1080, HTTP :1081
```

## Neden

Mevcut araçlarda zaman, protokolden çok yapılandırmaya gidiyor: JSON ağaçları,
inbound/outbound şemaları, sertifika işleri, panel kurulumları. prx'te
kullanıcı eklemek tek komut, o kullanıcının ihtiyaç duyduğu her şey tek bir
URL'de ve sunucuyu yeniden başlatmak gerekmiyor.

Buna karşılık kriptografide hiçbir şey icat edilmedi: TLS 1.3 (Go'nun
`crypto/tls`'i), HMAC-SHA256 ve RFC 5705 anahtar dışa aktarımı. Yeni olan tek
şey bunların nasıl birleştirildiği — aşağıda.

## Kurulum

**Sunucu** (Go 1.24+ gerekir):

```bash
git clone <bu-depo> && cd proxy
sudo ./scripts/install.sh                       # 443 portu, "default" kullanıcı
sudo ./scripts/install.sh --port 8443 --sni www.bing.com --user ali
```

Betik derler, `/usr/local/bin`'e kurar, `/etc/prx/server.json` oluşturur,
ilk kullanıcıyı ekler, systemd servisini yazıp başlatır ve bağlantı linkini
QR koduyla birlikte ekrana basar.

**İstemci** — sunucudan aldığınız linki verin:

```bash
prx 'prx://ANAHTAR@sunucu:443?sni=www.cloudflare.com#ev'
```

Tarayıcınızı `127.0.0.1:1080` SOCKS5 ya da `127.0.0.1:1081` HTTP proxy'sine
yönlendirin. Çalıştığını doğrulamak için:

```bash
prx test 'prx://...'
```

## SNI

SNI linkin içinde, istemci tarafında değiştirilebilir:

```bash
prx 'prx://ANAHTAR@sunucu:443?sni=www.apple.com'   # link ile
prx 'prx://ANAHTAR@sunucu:443' -sni www.apple.com  # bayrakla, linki ezer
```

Sunucu hangi isim istenirse ona uyan bir sertifika üretir; `www.apple.com`
isteyen `www.apple.com` için düzenlenmiş bir sertifika alır. Ağı izleyen biri
için bağlantı, o isme yapılmış sıradan bir HTTPS oturumu görünümündedir.

Bu sertifikanın güvenlikte hiçbir rolü yok — kimlik doğrulama bir kat yukarıda
yapılıyor (aşağıya bakın). Rolü yalnızca kamuflaj.

## Güvenlik modeli

TLS el sıkışması bittikten sonra iki taraf da oturumdan bir **kanal bağlayıcı**
türetir (RFC 5705 anahtar dışa aktarımı) ve ön paylaşımlı anahtarla bunun
üzerine bir HMAC üretip karşılıklı doğrular.

Sertifikanın doğrulanmaması bu yüzden bir eksiklik değil, tasarımın kendisi:

- **Araya girme (MITM).** TLS'i sonlandıran bir saldırgan istemci tarafında
  `B1`, sunucu tarafında `B2` bağlayıcısı elde eder. İstemcinin ürettiği etiket
  `B1` üzerinedir; sunucuya iletildiğinde `B2` ile karşılaştırılır ve tutmaz.
  Sunucunun etiketini üretmek için anahtar gerekir. Saldırgan hedeflenen SNI
  için **geçerli bir sertifikaya sahip olsa bile** bağlantı kopar.
- **Tekrar saldırısı (replay).** Her TLS oturumu yeni bir bağlayıcı üretir,
  kaydedilmiş bir etiket bir daha asla doğrulanmaz. Nonce veritabanı ya da saat
  senkronizasyonu gerekmez.
- **Aktif tarama (probing).** Anahtarı olmayan herkese sıradan bir web sitesi
  cevabı döner. Tarayıcıyla bakan bir nginx karşılama sayfası görür; port,
  başka herhangi bir HTTPS sunucusundan ayırt edilemez.

Ayrıca:

- Kimlik doğrulama kaydında **hiçbir kullanıcı tanımlayıcısı yok**. Sunucu
  anahtarı, her kullanıcı için beklenen etiketi hesaplayıp sabit zamanlı
  karşılaştırarak bulur. Hatta el sıkışma kayıtları rastgele dolgu ile
  boyutlandırılır, böylece TLS içinde sabit uzunlukta bir imza oluşmaz.
- Sunucu varsayılan olarak **özel adres aralıklarına** (127.0.0.0/8, RFC1918,
  100.64/10 …) bağlanmayı reddeder — açık bir proxy'nin operatörün kendi ağına
  kapı olmaması için. `allow_private` ile açılabilir.
- Varsayılan olarak **25. port kapalı** (spam rölesi olarak kullanılıp IP'nin
  kara listeye düşmemesi için). `block_ports` ile değiştirilebilir.
- systemd servisi ayrıcalıksız bir kullanıcı olarak, yalnızca
  `CAP_NET_BIND_SERVICE` ile ve sıkılaştırılmış olarak çalışır.

Ayrıntılı protokol tanımı: [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

### Bilinmesi gereken sınır

Varsayılan `cert_mode: auto`'da sertifika kendinden imzalıdır. Pasif izleme
için bir fark yaratmaz, ama porta **tarayıcıyla** bakan biri güven uyarısı
görür. Alan adınız varsa gerçek bir sertifika kullanın — o zaman aktif tarama
karşısında da site tamamen normal görünür:

```json
{ "cert_mode": "file", "cert_file": "/path/fullchain.pem", "key_file": "/path/key.pem" }
```

Aynı şekilde, dahili decoy sayfası bir tarayıcıya nginx gibi görünür ama
başlık sıralaması Go'nun HTTP sunucusuna aittir; bunu ölçen birine karşı
`fallback` ayarını gerçek bir web sunucusuna yöneltin — o zaman taklit değil,
gerçeğin kendisi olur.

## Performans

Tek akış, tam TLS şifrelemeli, SOCKS5 üzerinden — bu makinede (loopback,
`go1.26`, Linux 7.0):

| ölçüm | sonuç |
|---|---|
| tünel verimi (2 GiB indirme) | **~1,3 GB/s** (≈10 Gbit/s) |
| istek gecikmesi (sıcak havuz) | **~0,5 ms** |

Gecikmenin bu kadar düşük olmasının iki nedeni var:

- **Sıcak bağlantı havuzu.** İstemci birkaç bağlantıyı önceden kurup kimlik
  doğrulamasını yapıp bekletir. Yeni bir istek TCP, TLS ve kimlik doğrulama
  gidiş-dönüşlerinin hiçbirini ödemez.
- **Durum yanıtı yok.** İstemci hedefi bildirir bildirmez veri göndermeye
  başlar; ulaşılamayan hedef bağlantının kapanmasıyla bildirilir. Bu, her
  istekten tam bir RTT siler — 150 ms gecikmeli bir hatta 150 ms demek.

Aktarım yolunda bağlantı başına tahsis yok (havuzlanmış 32 KiB tamponlar),
`TCP_NODELAY` açık ve yarı-kapatma korunuyor.


## Android

Uygulama tüm cihazın trafiğini tünelden geçirir (`VpnService`). Go çekirdeği
masaüstüyle **aynı koddur**; `gomobile` ile `.aar` olarak derlenir, telefonun
IP paketleri `gvisor` tabanlı bir kullanıcı-alanı ağ yığınında bağlantılara
dönüştürülür ve tünele verilir.

Hazır APK: [**son sürümü indir**](https://github.com/justtahsin/prx/releases/latest)
(`arm64` neredeyse her telefon için doğru olanı). Kendiniz derlemek isterseniz:

```bash
make apk    # android/app/build/outputs/apk/release/ altına üç APK
```

APK'yı telefona aktarıp kurun (Bilinmeyen kaynaklara izin vermeniz gerekir).
Uygulamada: linki yapıştırın, isterseniz **SNI** alanını doldurun, Connect.

Uygulamadaki alanlar:

| alan | anlamı |
|---|---|
| Connection link | `prx://…` linki. `prx://` linkine tıklamak da uygulamayı açar. |
| SNI | TLS el sıkışmasında gönderilecek sunucu adı. Boş bırakılırsa linktekini kullanır. |
| TLS fingerprint | Hangi tarayıcının el sıkışması taklit edilsin. |
| Test | Bağlanmadan önce tüneli sınar, çıkış IP'sini gösterir. |

İki tasarım ayrıntısı önemli:

- **Kendi bağlantımız tünelden muaf.** Sunucuya giden soket
  `VpnService.protect()` ile işaretlenir; olmasaydı istemcinin trafiği
  taşıdığı tünelin içine yönlenir ve hiçbir şey çalışmazdı.
- **IPv6 de yakalanır.** Yakalanmasaydı IPv6 trafiği tünelin dışından
  sızardı — VPN'in tam olarak engellemesi gereken şey. Sunucunuzda IPv6 yoksa
  denemeler hızlıca başarısız olur ve uygulamalar IPv4'e döner.

DNS sorguları tünelin içinden UDP olarak gider, yani isimler karşı uçta
çözülür; yerel bir çözümleyici nereye gittiğinizi görmez.

## Sunucuyu bir VPS'e kurmak

Tek komut — sunucuda hiçbir şey kurulu olmasına gerek yok, ikili burada
çapraz derlenip yüklenir:

```bash
./scripts/deploy.sh root@sunucunuz.example.com
./scripts/deploy.sh root@sunucunuz.example.com --port 8443 --user telefon --sni www.bing.com
```

Betik: mimariyi tespit eder, `prxd`'yi derleyip yükler, systemd servisini
kurar, ufw/firewalld varsa portu açar ve telefona yapıştıracağınız linki
QR koduyla birlikte basar. Tekrar çalıştırmak güvenlidir — mevcut
yapılandırma korunur, yalnızca ikili ve servis yenilenir.

## Komutlar

**Sunucu**

```
prxd init [-c dosya] [-listen :443] [-host adres] [-sni ad] [-user ad]
prxd run [-c dosya] [-log seviye]
prxd user add <ad>          # ekle, link + QR bas (yeniden başlatma gerekmez)
prxd user ls                # listele
prxd user rm|enable|disable|rotate <ad>
prxd link <ad> [-sni ad] [-fp ad] [-no-qr]
prxd install [-c dosya] [-user prx]
```

**İstemci**

```
prx <link>                              # kısayol: prx run <link>
prx run <link> [-socks adres] [-http adres] [-sni ad] [-fp ad] [-pool n]
prx run -c client.json
prx test <link>                         # bağlantıyı sına, çıkış IP'sini yaz
prx show <link>                         # linkin içeriğini yaz
```

`-socks off` / `-http off` ilgili dinleyiciyi kapatır. `-fp` seçenekleri:
`chrome` (varsayılan), `firefox`, `safari`, `ios`, `edge`, `android`, `random`.

## Yapılandırma

`/etc/prx/server.json` — her alanın çalışan bir varsayılanı var, `{}` bile
geçerli bir dosyadır.

| alan | varsayılan | anlamı |
|---|---|---|
| `listen` | `:443` | dinlenecek adres |
| `cert_mode` | `auto` | `auto` (SNI'ye uyan sertifika üret) veya `file` |
| `cert_file` / `key_file` | — | `file` modunda sertifika ve anahtar |
| `fallback` | `""` | yetkisiz ziyaretçilerin yönlendirileceği web sunucusu; boşsa dahili sayfa |
| `users_file` | `users.json` | kimlik dosyası (config dizinine göreli) |
| `public_host` / `public_port` | otomatik | linklerde yazılacak adres |
| `default_sni` | `www.cloudflare.com` | üretilen linklerdeki SNI |
| `allow_private` | `false` | özel adres aralıklarına bağlanmaya izin ver |
| `block_ports` | `[25]` | reddedilecek hedef portlar |
| `log_level` | `info` | `error`, `warn`, `info`, `debug` |

Kullanıcı dosyası düz JSON'dur; elle düzenlenebilir ve değişiklik 5 saniye
içinde çalışan sunucuya yansır.

## Proje yapısı

```
cmd/prxd            sunucu ikilisi ve CLI
cmd/prx             istemci ikilisi ve CLI
mobile/             gomobile ile bağlanan Android çekirdeği (tun2socks köprüsü)
android/            Kotlin + Compose uygulaması, VpnService
internal/protocol   tel protokolü: adresler, istekler, dolgu, kimlik doğrulama
internal/server     daemon, sertifika üretimi, decoy, UDP
internal/client     tünel çevirici + sıcak havuz, SOCKS5, HTTP proxy
internal/users      kimlik deposu (atomik yazma, canlı yeniden yükleme)
internal/link       prx:// URL'lerini çözme ve üretme
internal/relay      iki yönlü kopyalama (havuzlanmış tamponlar, yarı-kapatma)
internal/e2e        gerçek soketler üzerinde uçtan uca testler
docs/PROTOCOL.md    ikinci bir implementasyon için referans
```

## Geliştirme

```bash
make build     # her iki ikili
make test      # test paketi
make race      # yarış dedektörüyle
make check     # gofmt + vet + race — CI'ın koşacağı her şey
make release   # linux/darwin/windows/android için çapraz derleme
make aar       # Go çekirdeğini Android kütüphanesi (.aar) olarak derle
make apk       # Android uygulamasını derle
```

## Yol haritası

Sunucu, masaüstü istemci, yönetim katmanı ve Android uygulaması hazır.
Sırada:

1. **Akış çoğullama (mux)** — mobilde pil ömrü için tek bağlantı üzerinden
   çok akış. Protokolde yeni bir komut olarak eklenecek, mevcut yapı bozulmaz.
3. **Kullanım istatistikleri** — kullanıcı başına trafik sayaçları ve kota.

## Lisans

MIT — bkz. [LICENSE](LICENSE).
