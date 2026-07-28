# Moves the pointer to a known place and clicks, through QEMU's control socket.
#
# Relative motion only. QEMU's absolute events are delivered to a tablet
# device, and the guest has a PS/2 mouse — which speaks three-byte packets with
# nine-bit deltas and nothing else. Sending `abs` moved the pointer somewhere
# unrelated to where it was asked for, which looked exactly like clicks not
# working.
#
# So: shove it hard into the top-left corner, where the driver clamps it, and
# then count from there. Each step stays inside what a packet can carry.
#
# Usage: powershell -File xtask/click.ps1 <x> <y> [left|right]

param(
    [int]$X = 640,
    [int]$Y = 400,
    [string]$Button = "left"
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
    Start-Sleep -Milliseconds 30
}

# Home. The driver clamps to the screen, so overshooting is how a relative
# device is given an absolute starting point.
#
# Negative dy is up. The mouse protocol has y growing upward and the guest's
# driver flips it, but QEMU's `rel` axis is already screen-oriented and it
# does the flip on the way in — so the two cancel and this script speaks
# screen coordinates. Assuming otherwise put the pointer at 537 when asked
# for 262, which is 800 minus 263: the sign was wrong and nothing else was.
for ($i = 0; $i -lt 12; $i++) { Move-Rel -120 -120 }

# Then count across. 120 per step, well inside the nine-bit delta a packet
# carries, and the driver discards anything it reads as an overflow.
$steps = [Math]::Ceiling([Math]::Max($X, $Y) / 120.0)
if ($steps -lt 1) { $steps = 1 }
for ($i = 1; $i -le $steps; $i++) {
    $dx = [int]($X * $i / $steps) - [int]($X * ($i - 1) / $steps)
    $dy = [int]($Y * $i / $steps) - [int]($Y * ($i - 1) / $steps)
    Move-Rel $dx $dy
}

Start-Sleep -Milliseconds 200
Send-Qmp ('{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":true,"button":"' + $Button + '"}}]}}')
Start-Sleep -Milliseconds 150
Send-Qmp ('{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":false,"button":"' + $Button + '"}}]}}')
Start-Sleep -Milliseconds 150

$client.Close()
Write-Output "$Button click at ($X, $Y)"
