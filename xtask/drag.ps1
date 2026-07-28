# Drags: presses at one point, moves in steps with the button held, releases.
#
# A separate script from click.ps1 because a drag is the one gesture that
# happens *while* a button is down rather than on its edge, and the guest
# follows it packet by packet. Sending the whole movement in one jump would
# test a teleport rather than a drag.
#
# Usage: powershell -File xtask/drag.ps1 <fromX> <fromY> <toX> <toY>

param(
    [int]$FromX = 400,
    [int]$FromY = 400,
    [int]$ToX = 600,
    [int]$ToY = 300
)

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

function Move-Rel($dx, $dy) {
    Send-Qmp ('{"execute":"input-send-event","arguments":{"events":[{"type":"rel","data":{"axis":"x","value":' + $dx + '}},{"type":"rel","data":{"axis":"y","value":' + $dy + '}}]}}')
    Start-Sleep -Milliseconds 25
}

# Home into the corner the driver clamps at, then count out. Same reasoning as
# click.ps1: the guest has a PS/2 mouse and only speaks relative movement.
for ($i = 0; $i -lt 12; $i++) { Move-Rel -120 -120 }
$steps = [Math]::Ceiling([Math]::Max($FromX, $FromY) / 120.0)
if ($steps -lt 1) { $steps = 1 }
for ($i = 1; $i -le $steps; $i++) {
    $dx = [int]($FromX * $i / $steps) - [int]($FromX * ($i - 1) / $steps)
    $dy = [int]($FromY * $i / $steps) - [int]($FromY * ($i - 1) / $steps)
    Move-Rel $dx $dy
}

Start-Sleep -Milliseconds 150
Send-Qmp '{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":true,"button":"left"}}]}}'
Start-Sleep -Milliseconds 150

# In steps, with the button still down. Ten of them, so the guest sees a drag
# rather than one large jump.
$dx = $ToX - $FromX
$dy = $ToY - $FromY
for ($i = 1; $i -le 10; $i++) {
    $sx = [int]($dx * $i / 10) - [int]($dx * ($i - 1) / 10)
    $sy = [int]($dy * $i / 10) - [int]($dy * ($i - 1) / 10)
    Move-Rel $sx $sy
}

Start-Sleep -Milliseconds 150
Send-Qmp '{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":false,"button":"left"}}]}}'
Start-Sleep -Milliseconds 150

$client.Close()
Write-Output "dragged ($FromX, $FromY) to ($ToX, $ToY)"
