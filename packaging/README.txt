WhisezOS Geliştirici Önizlemesi
==============================

Bu paket aşağıdaki dosyaları içerir:

  EFI/BOOT/BOOTX64.EFI
      Animasyonlu WhisezOS ejderhası ve masaüstünü gösteren UEFI önizlemesi.

  Tools/whisez-guard.exe
      Windows güvenlik denetimi, çevrimdışı tarama ve SHA3-256 bütünlük aracı.

  Wallpapers/whisezos-dragon-4k.png
      3840x2160 WhisezOS masaüstü duvar kâğıdı.

Whisez Guard hızlı başlangıç (PowerShell)
-----------------------------------------

  .\Tools\whisez-guard.exe audit
  .\Tools\whisez-guard.exe scan C:\incelenecek-klasor
  .\Tools\whisez-guard.exe baseline C:\onemli --output baseline.json
  .\Tools\whisez-guard.exe verify baseline.json
  .\Tools\whisez-guard.exe monitor baseline.json --interval 5

Tarayıcı yalnızca yerel çalışır. İncelediği dosyaları çalıştırmaz, internete
yüklemez, silmez ve otomatik karantinaya almaz.

UEFI masaüstü kontrolleri
-------------------------

  Fare hareketi         İmleci hareket ettirir ve kart seçer
  Sol tık               Kartı açar veya ekrandaki geri düğmesini etkinleştirir
  Sağ tık               Masaüstüne döner
  Yukarı/Aşağı veya W/S Guard, Terminal ya da Files seçer
  Enter                 Seçili ekranı açar
  1 / 2 / 3             İlgili ekranı doğrudan açar
  Esc                   Masaüstüne döner

Projenin mevcut sınırı
----------------------

EFI dosyası gerçekten açılabilen bir UEFI önizlemesidir; tamamlanmış bir
işletim sistemi değildir. Üretim çekirdeği, donanım sürücüleri, compositor
geçişi, disk kurucusu ve gerçek masaüstü oturumu hâlâ geliştirme aşamasındadır.
