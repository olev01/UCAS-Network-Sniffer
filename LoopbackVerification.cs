using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using ExperimentA.Core;
using ExperimentA.Windows;

namespace ExperimentA;

internal static class LoopbackVerification
{
    private static readonly byte[] Request = "GET /netscope-test HTTP/1.1\r\nHost: localhost\r\n\r\n"u8.ToArray();
    private static readonly byte[] Response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"u8.ToArray();
    private static readonly byte[] Datagram = "NetScope local UDP check"u8.ToArray();

    internal static int Run(string outputFile)
    {
        var results = new Results();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            VerifyAsync(results, timeout.Token).GetAwaiter().GetResult();
        }
        catch (Exception error)
        {
            results.Check(false, $"验证流程：{error.GetType().Name}，{error.Message}");
        }

        File.WriteAllLines(outputFile, results.Format(), new UTF8Encoding(false));
        return results.Failed == 0 ? 0 : 1;
    }

    private static async Task VerifyAsync(Results results, CancellationToken cancellation)
    {
        var adapters = NpcapCapture.ListAdapters();
        CaptureAdapter? adapter = adapters.FirstOrDefault(item =>
            item.Id.Equals(@"\Device\NPF_Loopback", StringComparison.OrdinalIgnoreCase));
        results.Check(adapter is not null, "Npcap 枚举到本机回环接口");
        if (adapter is null)
            return;

        using var ipv4 = new FamilyProbe(IPAddress.Loopback);
        using var ipv6 = AttachIpv6(results);
        FamilyProbe[] probes = ipv6 is null ? [ipv4] : [ipv4, ipv6];
        string filter = string.Join(" or ", probes.Select(probe => probe.CaptureFilter));
        using var capture = new NpcapCapture(adapter, filter);
        results.Check(capture.LinkType == 0, $"回环接口链路层类型 DLT_NULL（实际 {capture.LinkType}）");

        foreach (FamilyProbe probe in probes)
            await probe.ExchangeTrafficAsync(cancellation);

        var deadline = DateTime.UtcNow.AddSeconds(2);
        while (DateTime.UtcNow < deadline && probes.Any(probe => !probe.ObservedAll))
        {
            cancellation.ThrowIfCancellationRequested();
            if (!capture.TryRead(out byte[] data, out DateTimeOffset timestamp, out int wireLength))
            {
                await Task.Delay(10, cancellation);
                continue;
            }

            var packet = PacketDecoder.Decode(data, capture.LinkType, timestamp, wireLength);
            foreach (FamilyProbe probe in probes)
                probe.Observe(packet, data);
        }

        var lookup = new TcpProcessLookup();
        foreach (FamilyProbe probe in probes)
            probe.Report(lookup, results);
    }

    private static FamilyProbe? AttachIpv6(Results results)
    {
        if (!Socket.OSSupportsIPv6)
        {
            results.Skip("本机 IPv6 未启用");
            return null;
        }

        try
        {
            return new FamilyProbe(IPAddress.IPv6Loopback);
        }
        catch (SocketException error) when (error.SocketErrorCode is SocketError.AddressFamilyNotSupported
            or SocketError.AddressNotAvailable or SocketError.ProtocolNotSupported)
        {
            results.Skip($"IPv6 回环不可用（{error.SocketErrorCode}）");
            return null;
        }
    }

    private sealed class FamilyProbe : IDisposable
    {
        private readonly IPAddress _address;
        private readonly TcpListener _listener;
        private readonly TcpClient _client;
        private readonly UdpClient _udpReceiver;
        private readonly UdpClient _udpSender;
        private readonly byte[] _echoPattern = RandomNumberGenerator.GetBytes(24);
        private TcpClient? _server;
        private bool _sawRequest;
        private bool _sawResponse;
        private bool _sawUdp;
        private bool _sawIcmp;
        private bool _pingSucceeded;
        private TcpFlowKey? _requestKey;
        private TcpFlowKey? _responseKey;

        public FamilyProbe(IPAddress address)
        {
            _address = address;
            var listener = new TcpListener(address, 0);
            TcpClient? client = null;
            UdpClient? receiver = null;
            try
            {
                listener.Start();
                client = new TcpClient(new IPEndPoint(address, 0));
                receiver = new UdpClient(new IPEndPoint(address, 0));
                _udpSender = new UdpClient(new IPEndPoint(address, 0));
                _udpReceiver = receiver;
                _client = client;
                _listener = listener;
            }
            catch
            {
                receiver?.Dispose();
                client?.Dispose();
                listener.Stop();
                throw;
            }
        }

        private bool IsIpv4 => _address.AddressFamily == AddressFamily.InterNetwork;
        private string Family => IsIpv4 ? "IPv4" : "IPv6";
        private ushort ClientPort => Port(_client.Client.LocalEndPoint!);
        private ushort ServerPort => Port(_listener.LocalEndpoint);
        private ushort UdpSendPort => Port(_udpSender.Client.LocalEndPoint!);
        private ushort UdpReceivePort => Port(_udpReceiver.Client.LocalEndPoint!);

        public bool ObservedAll => _sawRequest && _sawResponse && _sawUdp && _sawIcmp;

        public string CaptureFilter
        {
            get
            {
                uint echoSignature = BinaryPrimitives.ReadUInt32BigEndian(_echoPattern);
                string icmp = IsIpv4
                    ? $"(icmp and icmp[8:4] = 0x{echoSignature:X8})"
                    : $"(icmp6 and ip6[48:4] = 0x{echoSignature:X8})";
                string tcp = $"(tcp and port {ClientPort} and port {ServerPort})";
                string udp = $"(udp and src port {UdpSendPort} and dst port {UdpReceivePort})";
                return $"(src host {_address} and dst host {_address} and ({tcp} or {udp} or {icmp}))";
            }
        }

        public async Task ExchangeTrafficAsync(CancellationToken cancellation)
        {
            await _client.ConnectAsync(_address, ServerPort, cancellation);
            _server = await _listener.AcceptTcpClientAsync(cancellation);

            NetworkStream clientStream = _client.GetStream();
            NetworkStream serverStream = _server.GetStream();
            await ExchangeAsync(clientStream, serverStream, Request, cancellation);
            await ExchangeAsync(serverStream, clientStream, Response, cancellation);

            _udpSender.Send(Datagram, new IPEndPoint(_address, UdpReceivePort));
            UdpReceiveResult received = await _udpReceiver.ReceiveAsync(cancellation);
            if (!received.Buffer.AsSpan().SequenceEqual(Datagram))
                throw new InvalidOperationException($"{Family} UDP 测试回环内容不匹配。");

            using var ping = new Ping();
            PingReply echo = await ping.SendPingAsync(_address, TimeSpan.FromMilliseconds(700),
                _echoPattern, options: null, cancellationToken: cancellation);
            _pingSucceeded = echo.Status == IPStatus.Success;
        }

        public void Observe(PacketInfo packet, byte[] data)
        {
            if (!_address.Equals(packet.Source) || !_address.Equals(packet.Destination))
                return;

            if (packet.Transport == TransportProtocol.Tcp)
            {
                if (packet.SourcePort == ClientPort && packet.DestinationPort == ServerPort && packet.IsHttp)
                {
                    _sawRequest = true;
                    _requestKey = TcpFlowKey.From(packet);
                }
                if (packet.SourcePort == ServerPort && packet.DestinationPort == ClientPort && packet.IsHttp)
                {
                    _sawResponse = true;
                    _responseKey = TcpFlowKey.From(packet);
                }
            }
            else if (packet.Transport == TransportProtocol.Udp)
            {
                _sawUdp |= packet.SourcePort == UdpSendPort && packet.DestinationPort == UdpReceivePort;
            }
            else if (packet.Transport == (IsIpv4 ? TransportProtocol.Icmp : TransportProtocol.IcmpV6))
            {
                _sawIcmp |= data.AsSpan().EndsWith(_echoPattern);
            }
        }

        public void Report(TcpProcessLookup lookup, Results results)
        {
            results.Check(_sawRequest, $"{Family} 捕获明文 HTTP 请求");
            results.Check(_sawResponse, $"{Family} 捕获明文 HTTP 响应");
            results.Check(_sawUdp, $"{Family} 捕获回环 UDP");
            results.Check(_sawIcmp && _pingSucceeded, $"{Family} 捕获回环 ICMP Echo");
            results.Check(_requestKey.HasValue && _requestKey == _responseKey,
                $"{Family} 双向报文归入同一 TCP 流");
            var owners = lookup.Find(_requestKey);
            results.Check(owners.Any(owner => owner.Id == Environment.ProcessId),
                $"{Family} TCP 流关联当前验证进程{(lookup.Error is null ? "" : $"（{lookup.Error}）")}");
        }

        public void Dispose()
        {
            _server?.Dispose();
            _client.Dispose();
            _listener.Stop();
            _udpReceiver.Dispose();
            _udpSender.Dispose();
        }

        private static async Task ExchangeAsync(NetworkStream sender, NetworkStream receiver, byte[] expected,
            CancellationToken cancellation)
        {
            var actual = new byte[expected.Length];
            await sender.WriteAsync(expected, cancellation);
            await receiver.ReadExactlyAsync(actual, cancellation);
            if (!actual.AsSpan().SequenceEqual(expected))
                throw new InvalidOperationException("TCP 测试回环内容不匹配。");
        }

        private static ushort Port(EndPoint endpoint) => checked((ushort)((IPEndPoint)endpoint).Port);
    }

    private sealed class Results
    {
        private readonly List<string> _entries = [];
        private int _passed;
        private int _skipped;
        public int Failed { get; private set; }

        public void Check(bool passed, string name)
        {
            if (passed)
                _passed++;
            else
                Failed++;
            _entries.Add($"{(passed ? "PASS" : "FAIL")} {name}");
        }

        public void Skip(string name)
        {
            _skipped++;
            _entries.Add($"SKIP {name}");
        }

        public IEnumerable<string> Format() =>
        [
            "NetScope 本机回环验证",
            .. _entries,
            $"通过 {_passed}，失败 {Failed}，跳过 {_skipped}"
        ];
    }
}
