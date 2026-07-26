# WhisezOS'a katkıda bulunma

WhisezOS; odaklı hata düzeltmelerini, testleri, belge iyileştirmelerini ve küçük
platform geliştirmelerini memnuniyetle karşılar. Üretim çekirdeği, sürücüler,
disk kurucusu ve gerçek masaüstü oturumu hâlâ araştırma/geliştirme aşamasındadır.
Tamamlanmamış kodu üretime hazır gibi gösteren değişiklikler kabul edilmez.

## Geliştirme ortamı

Önce [INSTALL.md](INSTALL.md) rehberini uygulayın, ardından:

```powershell
cargo xtask setup
cargo xtask test
```

Test komutu; Whisez Guard testlerini, ana bilgisayar doğrulama paketini, Clippy
denetimini ve UEFI önizleme derlemesini çalıştırır. `glslc` kurulu değilse shader
doğrulaması atlanır.

## Pull request kuralları

- Her pull request yalnızca tek bir probleme odaklansın.
- Davranış değiştiğinde test ekleyin veya mevcut testleri güncelleyin.
- Komutlar değişirse `README.md`, `INSTALL.md` ya da `BUILD.md` belgelerini de
  güncelleyin.
- Üretilen çıktıları, sanal makine durumunu, imzalama anahtarlarını ve yerel
  ayarları commit içine eklemeyin.
- Gerçek ad, kişisel e-posta, özel dosya yolu, erişim tokenı, kişisel bilgi
  içeren log veya taranan kullanıcı dosyası paylaşmayın.
- Pull request açmadan önce `cargo xtask test` komutunu çalıştırın.
- Projenin yapım aşamasında olduğunu ve fiziksel donanıma hazır olmadığını
  açıkça belirtin.

## Commit mesajları

Kısa ve neyin değiştiğini söyleyen mesajlar kullanın:

```text
Fix mouse selection in desktop preview
Add Turkish setup troubleshooting
Test capability revocation edge case
```

## Güvenlik bildirimleri

Olası bir güvenlik açığı için herkese açık issue açmayın. [SECURITY.md](SECURITY.md)
dosyasındaki özel güvenlik bildirimi yolunu kullanın.

Tüm katkılar Mozilla Public License 2.0 koşullarıyla lisanslanır.
