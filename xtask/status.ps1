# Asks QEMU what the guest is doing.
#
# `-no-shutdown` means a guest that powered off leaves QEMU running with the
# CPU stopped, rather than exiting. So "the process is still there" says
# nothing about whether the shutdown worked, and this is what does.

$ErrorActionPreference = "Stop"

$client = New-Object System.Net.Sockets.TcpClient
$client.Connect("127.0.0.1", 4444)
$stream = $client.GetStream()
$reader = New-Object System.IO.StreamReader($stream)
$writer = New-Object System.IO.StreamWriter($stream)
$writer.AutoFlush = $true

$null = $reader.ReadLine()
$writer.WriteLine('{"execute":"qmp_capabilities"}')
$null = $reader.ReadLine()

$writer.WriteLine('{"execute":"query-status"}')
while ($true) {
    $line = $reader.ReadLine()
    if ($null -eq $line) { break }
    if ($line -match '"return"|"error"') { Write-Output $line; break }
}

$client.Close()
