WhisezOS Developer Preview
==========================

This bundle contains:

  EFI/BOOT/BOOTX64.EFI
      Bootable UEFI preview with the animated WhisezOS dragon and desktop.

  Tools/whisez-guard.exe
      Defensive Windows posture, offline scan, and SHA3-256 integrity tool.

  Wallpapers/whisezos-dragon-4k.png
      3840x2160 WhisezOS desktop wallpaper.

Whisez Guard quick start (PowerShell)
-------------------------------------

  .\Tools\whisez-guard.exe audit
  .\Tools\whisez-guard.exe scan C:\path\to\inspect
  .\Tools\whisez-guard.exe baseline C:\important --output baseline.json
  .\Tools\whisez-guard.exe verify baseline.json
  .\Tools\whisez-guard.exe monitor baseline.json --interval 5

The scanner is local-only: it does not execute scanned files, upload data,
delete files, or quarantine anything automatically.

UEFI desktop controls
---------------------

  Mouse move           Move the visible cursor and select cards
  Left click           Open a card or activate the on-screen back button
  Right click          Return to the desktop
  Up / Down or W / S   Select Guard, Terminal, or Files
  Enter                Open the selected screen
  1 / 2 / 3            Open a screen directly
  Esc                  Return to the desktop

Status boundary
---------------

The EFI binary is a real bootable UEFI preview, not a finished operating
system. The production kernel, hardware drivers, compositor handoff, installer,
and desktop session remain under development.
