# Captures the guest's screen through QEMU's control socket.
#
# The serial log says what the kernel believes it printed. This says what a
# person looking at the machine actually sees, which is a different claim and
# the only one that settles an argument about the display.
#
# Usage: powershell -File xtask/screendump.ps1 [output.ppm]

param([string]$Out = "target/screen.ppm")

$ErrorActionPreference = "Stop"
$full = [IO.Path]::GetFullPath((Join-Path (Get-Location) $Out))
if (Test-Path $full) { Remove-Item $full -Force }

$client = New-Object System.Net.Sockets.TcpClient
$client.Connect("127.0.0.1", 4444)
$stream = $client.GetStream()
$reader = New-Object System.IO.StreamReader($stream)
$writer = New-Object System.IO.StreamWriter($stream)
$writer.AutoFlush = $true

# QMP opens with a greeting, and refuses every command until capabilities are
# negotiated. Both lines have to be read or the next reply is the previous
# command's.
$null = $reader.ReadLine()
$writer.WriteLine('{"execute":"qmp_capabilities"}')
$null = $reader.ReadLine()

$path = $full.Replace('\', '\\')
$writer.WriteLine("{`"execute`":`"screendump`",`"arguments`":{`"filename`":`"$path`"}}")

# Skip asynchronous events; the reply to a command is the first line carrying
# "return" or "error".
while ($true) {
    $line = $reader.ReadLine()
    if ($null -eq $line) { break }
    if ($line -match '"return"|"error"') { Write-Output $line; break }
}

$client.Close()

if (Test-Path $full) {
    $size = (Get-Item $full).Length
    Write-Output "captured $full ($size bytes)"
} else {
    Write-Output "no file was written"
}
