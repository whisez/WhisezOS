# WhisezOS kurulum ve çalıştırma rehberi

**[Türkçe](INSTALL.md) · [English](INSTALL.en.md)**

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
4. WhisezOS açılış animasyonunu, aşamalı kurulum provasını ve masaüstü
   önizlemesini gösterir.

Kurulum ekranı yaklaşık bir dakika sürer ve üretim kurulum sırasını gösterir;
**hiçbir diski okumaz veya yazmaz**. `Esc` ile atlayabilirsiniz.

QEMU penceresini kapattığınızda önizleme durur. Bilgisayarınızın fiziksel diski
bu işlem sırasında sanal makineye bağlanmaz.

## Kontroller

- Kurulum ekranında `Esc` provayı atlar.
- Fareyi kart veya dosya simgesi üzerine getirin, sol tıkla açın.
- Sağ tık veya `Esc` ile masaüstüne dönün.
- `Yukarı` / `Aşağı` ya da `W` / `S` ile seçim yapın.
- `Tab` ile uygulama sütunu ve dosya ızgarası arasında geçin.
- `Enter` ile seçili öğeyi açın.
- `1`–`5` ile bir uygulamayı doğrudan açın.
- `Ctrl+Alt+G` ile QEMU'nun yakaladığı fareyi serbest bırakın.

### Fare çalışmıyorsa

Üst çubuktaki `POINTER` göstergesine bakın. Bu sayı kaç işaretçi aygıtının
bağlandığını söyler.

QEMU ile gelen OVMF firmware'i hiçbir fare sürücüsü içermez: `EFI_SIMPLE_POINTER`
ve `EFI_ABSOLUTE_POINTER` protokollerini yalnızca konsol birleştiricisinin boş
sanal örnekleri olarak sunar, bu yüzden fareyi ne kadar oynatırsanız oynatın veri
gelmez. Önizleme bu durumu algılar ve i8042 yardımcı portundan PS/2 faresini
doğrudan sürer; göstergede `POINTER 1` görürsünüz.

`NO POINTER DEVICE` yazıyorsa ne firmware bir aygıt sunuyor ne de bir i8042
denetleyicisi var. Önizlemenin tamamı klavyeyle kullanılabilir.

## Üretim çekirdeğini çalıştırma

Önizleme bir çekirdek açmaz. Gerçek yükleyiciyi ve mikroçekirdeği QEMU'da
çalıştırmak için:

```powershell
cargo xtask boot-run
```

Bu komut üretim UEFI yükleyicisini ve çekirdek ELF'ini derler, geçici bir EFI
bölümüne yerleştirir ve QEMU'yu başlatır. Çekirdeğin tek çıktısı seri porttur;
komut seri portu terminale bağlar, ekran penceresi açılmaz.

Beklenen çıktı şu sırayla gelir: yükleyici bellek denetimi, çekirdek ELF'inin
doğrulanması, boot servislerinden çıkış, devir, ardından çekirdeğin GDT, IDT,
çerçeve ayırıcı ve sayfa tablosu satırları ve `[kernel] stage 1 complete`.

Ardından ikinci aşama gelir: çekirdek `init` imajını kendi kullanıcı adres
uzayına haritalar ve ring 3'e geçer. `[init]` ile başlayan satırlar kullanıcı
alanından, `syscall` üzerinden yazılır. Üç tanesi kasıtlı ihlaldir ve
reddedilmeleri beklenir — çekirdek belleğini okutmaya çalışmak, sınırı aşan bir
uzunluk vermek ve tanımsız bir syscall numarası çağırmak.

Aynı önyüklemeyi otomatik doğrulamak için:

```powershell
cargo xtask boot-test
```

Bu komut QEMU'yu başsız çalıştırır, seri günlüğü yakalar ve yirmi iki aşamanın
sırasıyla göründüğünü doğrular. `cargo xtask test` içinde de çalışır; QEMU
kurulu değilse uyarıyla atlanır.

> Üretim yükleyicisi projenin kendi 8 GiB bellek tabanını uygular ve altındaki
> bir platformu açmayı reddeder. Bu yüzden sanal makine 9 GiB ile başlatılır.

> `init` çıktıktan sonra sistem durur. Zamanlayıcı, süreç tablosu ve gerçek IPC
> henüz yok, dolayısıyla çalıştırılacak ikinci bir şey de yok. Bu, tamamlanmış
> bir işletim sistemi değil, doğrulanabilir ikinci dikey dilimdir.

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
DC79DB14ECBA5F431DFBB23B5F70586CB95E2A7903175A19AA85F4AA0235819F
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
