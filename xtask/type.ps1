# Types a line into the guest's shell through QEMU's control socket.
#
# The keys go through the emulated i8042, so the guest sees exactly what real
# hardware would produce — which is the only way to check a shell without a
# person sitting at it.
#
# Usage: powershell -File xtask/type.ps1 "help"

param([string]$Line = "help")

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

# QMP names keys by qcode, not by character, so the mapping is explicit. Only
# what a command line needs: letters, digits, space, and return.
$qcode = @{
    'a'='a';'b'='b';'c'='c';'d'='d';'e'='e';'f'='f';'g'='g';'h'='h';'i'='i'
    'j'='j';'k'='k';'l'='l';'m'='m';'n'='n';'o'='o';'p'='p';'q'='q';'r'='r'
    's'='s';'t'='t';'u'='u';'v'='v';'w'='w';'x'='x';'y'='y';'z'='z'
    '0'='0';'1'='1';'2'='2';'3'='3';'4'='4';'5'='5';'6'='6';'7'='7';'8'='8';'9'='9'
    ' '='spc'
}

foreach ($ch in $Line.ToCharArray()) {
    $key = $qcode[[string]$ch]
    if (-not $key) { Write-Output "skipping '$ch': no qcode for it"; continue }
    Send-Qmp ('{"execute":"input-send-event","arguments":{"events":[{"type":"key","data":{"down":true,"key":{"type":"qcode","data":"' + $key + '"}}}]}}')
    Send-Qmp ('{"execute":"input-send-event","arguments":{"events":[{"type":"key","data":{"down":false,"key":{"type":"qcode","data":"' + $key + '"}}}]}}')
    # The emulated i8042 exposes a one-byte output register. Giving the guest
    # time to drain each make/break pair prevents the next key from replacing
    # it during slow password hashing or a full-screen repaint.
    Start-Sleep -Milliseconds 90
}

Start-Sleep -Milliseconds 180
Send-Qmp '{"execute":"input-send-event","arguments":{"events":[{"type":"key","data":{"down":true,"key":{"type":"qcode","data":"ret"}}}]}}'
Send-Qmp '{"execute":"input-send-event","arguments":{"events":[{"type":"key","data":{"down":false,"key":{"type":"qcode","data":"ret"}}}]}}'

$client.Close()
Write-Output "typed: $Line"
