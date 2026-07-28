# Converts a QEMU screendump (binary PPM) to PNG.
#
# QEMU writes P6 PPM, which nothing on Windows opens. This is the smallest
# thing that turns a capture into something a person or a model can look at.
#
# Usage: powershell -File xtask/topng.ps1 target/screen.ppm target/screen.png

param(
    [string]$In = "target/screen.ppm",
    [string]$Out = "target/screen.png"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$bytes = [IO.File]::ReadAllBytes((Resolve-Path $In))

# The P6 header is four whitespace-separated fields — magic, width, height, and
# the maximum channel value — followed by exactly one whitespace byte before
# the pixels. Parsed by scanning rather than by a fixed offset, because the
# header's length depends on how many digits the dimensions take.
$pos = 0
$fields = @()
while ($fields.Count -lt 4) {
    while ([char]$bytes[$pos] -match '\s') { $pos++ }
    $token = ""
    while (-not ([char]$bytes[$pos] -match '\s')) { $token += [char]$bytes[$pos]; $pos++ }
    $fields += $token
}
$pos++

if ($fields[0] -ne "P6") { throw "not a binary PPM: magic is $($fields[0])" }
$w = [int]$fields[1]
$h = [int]$fields[2]

$bmp = New-Object System.Drawing.Bitmap($w, $h)
$rect = New-Object System.Drawing.Rectangle(0, 0, $w, $h)
$data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::WriteOnly,
                      [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
$row = New-Object byte[] ($data.Stride)
for ($y = 0; $y -lt $h; $y++) {
    for ($x = 0; $x -lt $w; $x++) {
        $src = $pos + ($y * $w + $x) * 3
        # PPM is RGB; the bitmap wants BGR.
        $row[$x * 3 + 0] = $bytes[$src + 2]
        $row[$x * 3 + 1] = $bytes[$src + 1]
        $row[$x * 3 + 2] = $bytes[$src + 0]
    }
    [System.Runtime.InteropServices.Marshal]::Copy($row, 0,
        [IntPtr]::Add($data.Scan0, $y * $data.Stride), $data.Stride)
}
$bmp.UnlockBits($data)
$bmp.Save((Join-Path (Get-Location) $Out), [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()

Write-Output "$Out (${w}x${h})"
