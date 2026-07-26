# WhisezOS kurulum ve çalıştırma rehberi

WhisezOS şu anda yalnızca QEMU için bir geliştirici önizlemesidir. Fiziksel
diske kendini kurmaz, Windows önyükleyicisini değiştirmez ve firmware ayarlarına
dokunmaz.

> [!CAUTION]
> Bu sürümü gerçek bilgisayara, USB diske veya ana işletim sisteminizin yanına
> kurmaya çalışmayın. Disk kurucusu ve donanım desteği henüz hazır değildir.

## Gereksinimler

Doğrulanmış hızlı başlangıç ortamı 64 bit Windows 10 veya Windows 11'dir:

- Depoyu indirmek için Git
- Sabitlenmiş Rust nightly araç zinciri için Rustup
- Sanal makine ve EDK2/OVMF firmware için QEMU
- İlk kurulum sırasında internet bağlantısı

## 1. Gerekli araçları kurun

PowerShell veya Windows Terminal'i açın:

```powershell
winget install --id Git.Git --exact
winget install --id Rustlang.Rustup --exact
winget install --id SoftwareFreedomConservancy.QEMU --exact
```

Kurulum bittikten sonra terminali kapatıp yeniden açın. Şu komutlarla araçların
görüldüğünü kontrol edebilirsiniz:

```powershell
git --version
rustup --version
qemu-system-x86_64 --version
```

## 2. WhisezOS'u indirin

```powershell
git clone https://github.com/whisez/WhisezOS.git
Set-Location WhisezOS
```

## 3. Geliştirme ortamını hazırlayın

```powershell
cargo xtask setup
```

Bu komut `rust-toolchain.toml` içinde sabitlenen Rust sürümünü ve gerekli UEFI
hedefini hazırlar. İlk çalıştırma, bağımlılıklar indirildiği için birkaç dakika
sürebilir.

## 4. UEFI önizlemesini QEMU'da açın

```powershell
cargo xtask run
```

Komut şu işlemleri otomatik yapar:

1. Gerçek UEFI uygulamasını release modunda derler.
2. QEMU için geçici ve özel bir firmware değişken dosyası oluşturur.
3. EDK2/OVMF firmware ile sanal makineyi başlatır.
4. WhisezOS açılış animasyonu ve masaüstü önizlemesini gösterir.

QEMU penceresini kapattığınızda önizleme durur. Bilgisayarınızın fiziksel diski
bu işlem sırasında sanal makineye bağlanmaz.

## Kontroller

- Fareyi hareket ettirerek kart seçin, sol tıkla açın.
- Sağ tık veya `Esc` ile masaüstüne dönün.
- `Yukarı` / `Aşağı` ya da `W` / `S` ile seçim yapın.
- `Enter` ile seçili uygulamayı açın.
- `1`, `2`, `3` ile Guard, Terminal veya Files uygulamasını açın.
- `Ctrl+Alt+G` ile QEMU'nun yakaladığı fareyi serbest bırakın.

## Yalnızca derleme

QEMU'yu başlatmadan EFI uygulamasını derlemek için:

```powershell
cargo xtask demo
```

Oluşan dosya:

```text
target/x86_64-unknown-uefi/release/spectre-demo.efi
```

EFI, Whisez Guard ve 4K duvar kâğıdını tek klasörde toplamak için:

```powershell
cargo xtask bundle
```

Paket `dist/WhisezOS` içine yazılır:

```text
dist/WhisezOS/
├── EFI/BOOT/BOOTX64.EFI
├── Tools/whisez-guard.exe
├── Wallpapers/whisezos-dragon-4k.png
└── README.txt
```

## Hazır paketi indirme

Kaynak kodu derlemeden dosyaları incelemek için:

**[WhisezOS v0.1.0 Developer Preview ZIP](https://github.com/whisez/WhisezOS/releases/download/v0.1.0/WhisezOS-v0.1.0-developer-preview.zip)**

ZIP dosyasının SHA-256 değeri:

```text
808B2D3F3249A1DF5516311ED259CEB2D730D1CFDB8B8B07AF733DD97CED61F6
```

Bu paket tek başına bir Windows kurucusu değildir. UEFI önizlemesini en kolay
ve güvenli biçimde çalıştırmak için kaynak kod yolundaki `cargo xtask run`
komutunu kullanın.

## Yalnızca Whisez Guard kullanımı

Whisez Guard, QEMU olmadan ayrı olarak derlenip kullanılabilir:

```powershell
cargo build --release -p whisez-guard
./target/release/whisez-guard.exe audit
./target/release/whisez-guard.exe scan C:\incelenecek-klasor
```

Araç yerel çalışır; incelediği dosyaları çalıştırmaz, yüklemez, silmez veya
otomatik karantinaya almaz.

## Kurulumu doğrulama

Tüm desteklenen test, lint ve UEFI derleme kontrollerini çalıştırın:

```powershell
cargo xtask test
```

Doğrulama sınırı 234 test içerir: 231 çekirdek/dosya sistemi/önyükleme mantığı
testi ve 3 Whisez Guard testi.

## Sorun çözme

### `QEMU not found`

Şu dosyanın varlığını kontrol edin:

```text
C:\Program Files\qemu\qemu-system-x86_64.exe
```

Dosya yoksa yukarıdaki Winget komutuyla QEMU'yu yeniden kurun ve terminali
yeniden açın.

### `UEFI firmware not found`

Windows QEMU paketi EDK2 firmware dosyalarını `share` klasöründe taşımalıdır.
`edk2-x86_64-code.fd` gibi dosyalar yoksa QEMU paketini yeniden kurun.

### Rust toolchain veya target hatası

```powershell
cargo xtask setup
```

Projenin sabitlediği nightly sürümü, gelişigüzel `nightly` sürümüyle
değiştirmeyin; tekrarlanabilir derleme için tarihli sürüm kullanılır.

### QEMU açılıyor ama siyah ekran kalıyor

- Birkaç saniye bekleyin; ilk derleme ve açılış normalden uzun sürebilir.
- Terminalde hata mesajı olup olmadığını kontrol edin.
- QEMU ve Rust araç zincirini güncel kurulum komutlarıyla yeniden hazırlayın.
- Sorun devam ederse kişisel bilgi içermeyen terminal çıktısıyla GitHub Issue
  açın.

### Linux ve macOS

Windows hızlı başlangıç yolu doğrulanmıştır. Linux ve macOS geliştiricileri
QEMU/OVMF yolları ve üretim araç zinciri ayrıntıları için [BUILD.md](BUILD.md)
dosyasını okumalıdır.

## Kaldırma

WhisezOS Windows'a servis kurmaz ve fiziksel diske yazmaz. Kaldırmak için QEMU
penceresini kapatıp klonladığınız `WhisezOS` klasörünü silmeniz yeterlidir.
Git, Rustup ve QEMU ayrı programlardır; artık kullanmayacaksanız Windows
Ayarları'ndan kaldırabilirsiniz.
