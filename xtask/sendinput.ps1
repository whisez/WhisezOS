# Sends keystrokes and mouse movement to the guest through QEMU's control
# socket.
#
# The point is to test input without a person. A driver that claims to handle a
# keyboard and a mouse is only shown to by something pressing keys and moving a
# mouse, and asserting on what the screen does afterwards — which is the one
# check a serial log cannot make.
#
# Usage: powershell -File xtask/sendinput.ps1 [keys] [dx] [dy]

param(
    [int]$Keys = 3,
    [int]$Dx = 220,
    [int]$Dy = 140
)

$ErrorActionPreference = "Stop"

$client = New-Object System.Net.Sockets.TcpClient
$client.Connect("127.0.0.1", 4444)
$stream = $client.GetStream()
$reader = New-Object System.IO.StreamReader($stream)
$writer = New-Object System.IO.StreamWriter($stream)
$writer.AutoFlush = $true

# QMP refuses every command until capabilities are negotiated, and the greeting
# has to be consumed or the next read returns it instead of a reply.
$null = $reader.ReadLine()
$writer.WriteLine('{"execute":"qmp_capabilities"}')
$null = $reader.ReadLine()

function Send-Qmp($json) {
    $writer.WriteLine($json)
    while ($true) {
        $line = $reader.ReadLine()
        if ($null -eq $line) { return }
        if ($line -match '"return"|"error"') {
            if ($line -match '"error"') { Write-Output "error: $line" }
            return
        }
    }
}

# Keys, as press-and-release pairs. `input-send-event` delivers through the
# emulated i8042, so the guest sees exactly what real hardware would produce.
for ($i = 0; $i -lt $Keys; $i++) {
    $key = @("a", "b", "c", "d", "e")[$i % 5]
    Send-Qmp ('{"execute":"input-send-event","arguments":{"events":[{"type":"key","data":{"down":true,"key":{"type":"qcode","data":"' + $key + '"}}}]}}')
    Send-Qmp ('{"execute":"input-send-event","arguments":{"events":[{"type":"key","data":{"down":false,"key":{"type":"qcode","data":"' + $key + '"}}}]}}')
}

# Relative motion, in several steps. One large jump would exceed what a PS/2
# packet can carry in its nine-bit deltas and be reported as an overflow, which
# the driver discards — so this moves the way a hand does.
$steps = 8
for ($i = 0; $i -lt $steps; $i++) {
    $sx = [int]($Dx / $steps)
    $sy = [int]($Dy / $steps)
    Send-Qmp ('{"execute":"input-send-event","arguments":{"events":[{"type":"rel","data":{"axis":"x","value":' + $sx + '}},{"type":"rel","data":{"axis":"y","value":' + $sy + '}}]}}')
    Start-Sleep -Milliseconds 40
}

$client.Close()
Write-Output "sent $Keys key(s) and a move of ($Dx, $Dy)"
