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


WhisezOS Developer Preview
==========================

This package contains:

  EFI/BOOT/BOOTX64.EFI
      UEFI preview displaying the animated WhisezOS dragon and desktop.

  Tools/whisez-guard.exe
      Windows security audit, offline scan, and SHA3-256 integrity utility.

  Wallpapers/whisezos-dragon-4k.png
      3840x2160 WhisezOS desktop wallpaper.

Whisez Guard quick start (PowerShell)
-------------------------------------

  .\Tools\whisez-guard.exe audit
  .\Tools\whisez-guard.exe scan C:\directory-to-scan
  .\Tools\whisez-guard.exe baseline C:\important --output baseline.json
  .\Tools\whisez-guard.exe verify baseline.json
  .\Tools\whisez-guard.exe monitor baseline.json --interval 5

The scanner operates locally. It does not execute, upload, delete, or
automatically quarantine inspected files.

UEFI desktop controls
---------------------

  Pointer movement       Moves the pointer and selects a card
  Left click             Opens a card or activates the on-screen back button
  Right click            Returns to the desktop
  Up/Down or W/S         Selects Guard, Terminal, or Files
  Enter                  Opens the selected screen
  1 / 2 / 3              Opens the corresponding screen directly
  Esc                    Returns to the desktop

Current project boundary
------------------------

The EFI application is a genuinely bootable UEFI preview, not a complete
operating system. The production kernel, hardware drivers, compositor
transition, disk installer, and real desktop session remain under development.
