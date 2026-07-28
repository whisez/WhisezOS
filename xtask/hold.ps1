# Presses a mouse button and leaves it down.
#
# A diagnostic, not a feature. The session draws a marker in the panel while a
# button is held, so this answers a question a click cannot: whether button
# state reaches the driver at all, separately from whether the click edge is
# detected correctly.

param([string]$Button = "left", [switch]$Release)

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

$down = if ($Release) { "false" } else { "true" }
$writer.WriteLine('{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":' + $down + ',"button":"' + $Button + '"}}]}}')
while ($true) {
    $line = $reader.ReadLine()
    if ($null -eq $line) { break }
    if ($line -match '"return"|"error"') { Write-Output $line; break }
}

$client.Close()
