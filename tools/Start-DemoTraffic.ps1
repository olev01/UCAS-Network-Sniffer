[CmdletBinding()]
param(
    [ValidateRange(1, 300)]
    [int] $DurationSeconds = 30,

    [ValidateRange(150, 5000)]
    [int] $IntervalMilliseconds = 850,

    [string] $TrafficInfoPath
)

$ErrorActionPreference = 'Stop'

function Read-DemoMessage {
    param(
        [Parameter(Mandatory)]
        [System.IO.Stream] $Stream,

        [Parameter(Mandatory)]
        [int] $Length
    )

    $buffer = [byte[]]::new($Length)
    $offset = 0
    while ($offset -lt $Length) {
        $read = $Stream.Read($buffer, $offset, $Length - $offset)
        if ($read -eq 0) {
            throw 'A local TCP endpoint closed before the synthetic HTTP message arrived.'
        }
        $offset += $read
    }
}

$loopback = [Net.IPAddress]::Loopback
$client = $server = $udpReceiver = $udpSender = $ping = $null
$tcpListener = [Net.Sockets.TcpListener]::new($loopback, 0)

try {
    $tcpListener.Start()
    $tcpPort = $tcpListener.LocalEndpoint.Port
    $client = [Net.Sockets.TcpClient]::new()
    $client.Connect($loopback, $tcpPort)
    $server = $tcpListener.AcceptTcpClient()
    $client.NoDelay = $server.NoDelay = $true
    $clientStream = $client.GetStream()
    $serverStream = $server.GetStream()
    $clientStream.ReadTimeout = $serverStream.ReadTimeout = 2000
    $clientStream.WriteTimeout = $serverStream.WriteTimeout = 2000

    $udpReceiver = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new($loopback, 0))
    $udpTarget = $udpReceiver.Client.LocalEndPoint
    $udpReceiver.Client.ReceiveTimeout = 2000
    $udpSender = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new($loopback, 0))

    $ascii = [Text.Encoding]::ASCII
    $request = $ascii.GetBytes("GET /demo HTTP/1.1`r`nHost: 127.0.0.1:$tcpPort`r`nConnection: keep-alive`r`n`r`n")
    $response = $ascii.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: 2`r`nConnection: keep-alive`r`n`r`nOK")
    $datagram = $ascii.GetBytes('NetScope local UDP demo')
    $echoMarker = $ascii.GetBytes('NSCP demo echo')
    $ping = [Net.NetworkInformation.Ping]::new()
    $sendIpv4Ping = $true
    $sendIpv6Ping = [Net.Sockets.Socket]::OSSupportsIPv6

    if ($TrafficInfoPath) {
        $trafficInfo = @{
            TcpClientPort = $client.Client.LocalEndPoint.Port
            TcpServerPort = $tcpPort
            UdpSourcePort = $udpSender.Client.LocalEndPoint.Port
            UdpTargetPort = $udpTarget.Port
        } | ConvertTo-Json -Compress
        $trafficInfo | Set-Content -LiteralPath $TrafficInfoPath -Encoding utf8
    }

    Write-Host "Npcap loopback demo for $DurationSeconds seconds (PowerShell PID $PID)"
    Write-Host "HTTP/1.1 on TCP port $tcpPort and UDP port $($udpTarget.Port)"
    Write-Host 'All traffic stays on this computer. Use Ctrl+C to stop early.'

    $timer = [Diagnostics.Stopwatch]::StartNew()
    $rounds = 0
    do {
        $clientStream.Write($request, 0, $request.Length)
        Read-DemoMessage -Stream $serverStream -Length $request.Length
        $serverStream.Write($response, 0, $response.Length)
        Read-DemoMessage -Stream $clientStream -Length $response.Length

        [void] $udpSender.Send($datagram, $datagram.Length, $udpTarget)
        $udpSource = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
        [void] $udpReceiver.Receive([ref] $udpSource)

        if ($sendIpv4Ping) {
            try {
                $sendIpv4Ping = $ping.Send($loopback, 300, $echoMarker).Status -eq [Net.NetworkInformation.IPStatus]::Success
            } catch {
                $sendIpv4Ping = $false
            }
            if (-not $sendIpv4Ping) { Write-Warning 'IPv4 loopback ping failed on this machine.' }
        }
        if ($sendIpv6Ping) {
            try {
                $sendIpv6Ping = $ping.Send([Net.IPAddress]::IPv6Loopback, 300, $echoMarker).Status -eq [Net.NetworkInformation.IPStatus]::Success
            } catch {
                $sendIpv6Ping = $false
            }
            if (-not $sendIpv6Ping) { Write-Warning 'IPv6 loopback ping failed on this machine.' }
        }

        $rounds++
        $millisecondsLeft = ($DurationSeconds * 1000) - $timer.ElapsedMilliseconds
        if ($millisecondsLeft -gt 0) {
            Start-Sleep -Milliseconds ([Math]::Min($millisecondsLeft, $IntervalMilliseconds))
        }
    } while ($timer.Elapsed.TotalSeconds -lt $DurationSeconds)

    Write-Host "Completed $rounds rounds of local HTTP and UDP traffic."
}
finally {
    foreach ($resource in @($client, $server, $udpSender, $udpReceiver, $ping)) {
        if ($null -ne $resource) { $resource.Dispose() }
    }
    $tcpListener.Stop()
}
