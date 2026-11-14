using ExperimentA.Core;
using static ExperimentA.Checks.TestFrames;

namespace ExperimentA.Checks;

internal static class Program
{
    private const int EthernetLinkType = 1;
    private const int LoopbackLinkType = 0;
    private const int RawIpLinkType = 12;
    private const ushort ClientPort = 49320;
    private const ushort WebPort = 8080;
    private static readonly DateTimeOffset Timestamp = new(2026, 11, 14, 10, 30, 0, TimeSpan.Zero);

    private static int Main()
    {
        (string Name, Action Run)[] checks =
        [
            ("Ethernet IPv4 HTTP request on a nonstandard port", DecodesHttpRequest),
            ("Ethernet IPv4 HTTP response", DecodesHttpResponse),
            ("Binary and incomplete TCP payloads are not HTTP", RejectsFalseHttpLabels),
            ("802.1Q Ethernet IPv4 UDP", DecodesTaggedUdp),
            ("IPv4 ICMP echo", DecodesIcmp),
            ("IPv6 ICMP echo with an extension header", DecodesIcmpV6),
            ("DLT_NULL IPv4 and IPv6 loopback", DecodesLoopback),
            ("Raw IP supports both address families", DecodesRawIp),
            ("Non-first IPv4 fragment has no transport ports", HandlesLaterIpv4Fragment),
            ("Ethernet padding is excluded from TCP payload", IgnoresEthernetPadding),
            ("Every truncated prefix is handled safely", HandlesTruncatedPrefixes),
            ("Unknown link type is handled safely", HandlesUnknownLinkType),
            ("TCP flow key is direction-independent", GroupsBothFlowDirections),
            ("TCP flow key distinguishes connections", SeparatesDifferentFlows),
            ("Protocol selections match decoded packet types", FiltersProtocols),
        ];

        int failed = 0;
        foreach ((string name, Action run) in checks)
        {
            try
            {
                run();
                Console.WriteLine($"PASS {name}");
            }
            catch (Exception error)
            {
                failed++;
                Console.Error.WriteLine($"FAIL {name}: {error.Message}");
            }
        }

        Console.WriteLine($"{checks.Length - failed}/{checks.Length} checks passed.");
        return failed == 0 ? 0 : 1;
    }

    private static void DecodesHttpRequest()
    {
        byte[] frame = RequestFrame();
        PacketInfo packet = Decode(frame);
        Equal(Timestamp, packet.Timestamp, "timestamp");
        Equal(frame.Length, packet.CapturedLength, "captured length");
        Equal(frame.Length, packet.WireLength, "wire length");
        Equal(4, packet.IpVersion, "IP version");
        Equal(LocalIpv4, packet.Source, "source address");
        Equal(RemoteIpv4, packet.Destination, "destination address");
        Equal(TransportProtocol.Tcp, packet.Transport, "transport");
        Equal<ushort?>(ClientPort, packet.SourcePort, "source port");
        Equal<ushort?>(WebPort, packet.DestinationPort, "destination port");
        Require(packet.IsHttp, "A complete HTTP request on port 8080 should be recognized.");
        Require(!string.IsNullOrWhiteSpace(packet.Summary), "Expected a packet summary.");
        Require(!string.IsNullOrWhiteSpace(packet.Details), "Expected packet details.");
    }

    private static void DecodesHttpResponse()
    {
        PacketInfo packet = Decode(ResponseFrame());
        Equal(RemoteIpv4, packet.Source, "source address");
        Equal(LocalIpv4, packet.Destination, "destination address");
        Equal<ushort?>(WebPort, packet.SourcePort, "source port");
        Equal<ushort?>(ClientPort, packet.DestinationPort, "destination port");
        Require(packet.IsHttp, "Expected the plaintext HTTP response to be recognized.");
    }

    private static void RejectsFalseHttpLabels()
    {
        PacketInfo binary = Decode(Ethernet(0x0800, Ipv4(6, Tcp(ClientPort, 80, [0x16, 3, 3, 0, 4, 1]))));
        PacketInfo partial = Decode(Ethernet(0x0800, Ipv4(6, Tcp(ClientPort, 80, "GET /lab"u8.ToArray()))));
        Equal(TransportProtocol.Tcp, binary.Transport, "binary payload transport");
        Equal(TransportProtocol.Tcp, partial.Transport, "partial payload transport");
        Require(!binary.IsHttp, "Binary data on a common HTTP port is not a request or response.");
        Require(!partial.IsHttp, "An incomplete request line should not be labeled HTTP.");
    }

    private static void DecodesTaggedUdp()
    {
        PacketInfo packet = Decode(Ethernet(0x0800, Ipv4(17, Udp(54_100, 80, HttpRequest)), vlan: true));
        Equal(4, packet.IpVersion, "IP version behind VLAN tag");
        Equal(TransportProtocol.Udp, packet.Transport, "transport");
        Equal<ushort?>(54_100, packet.SourcePort, "source port");
        Equal<ushort?>(80, packet.DestinationPort, "destination port");
        Require(!packet.IsHttp, "Matching text inside a UDP packet is not plaintext HTTP over TCP.");
        Require(TcpFlowKey.From(packet) is null, "UDP should not have a TCP flow key.");
    }

    private static void DecodesIcmp()
    {
        PacketInfo packet = Decode(Ethernet(0x0800, Ipv4(1, Icmp(8))));
        Equal(4, packet.IpVersion, "IP version");
        Equal(TransportProtocol.Icmp, packet.Transport, "transport");
        Equal<ushort?>(null, packet.SourcePort, "ICMP source port");
    }

    private static void DecodesIcmpV6()
    {
        byte[] frame = Ethernet(0x86dd, Ipv6(0, Ipv6HopByHop(58, Icmp(128))));
        PacketInfo packet = Decode(frame);
        Equal(6, packet.IpVersion, "IP version");
        Equal(LocalIpv6, packet.Source, "source address");
        Equal(RemoteIpv6, packet.Destination, "destination address");
        Equal(TransportProtocol.IcmpV6, packet.Transport, "transport behind extension header");
    }

    private static void DecodesLoopback()
    {
        PacketInfo ipv4 = Decode(Loopback(2, Ipv4(6, Tcp(ClientPort, WebPort, HttpRequest))), LoopbackLinkType);
        PacketInfo ipv6 = Decode(Loopback(24, Ipv6(58, Icmp(128))), LoopbackLinkType);
        Equal(4, ipv4.IpVersion, "IPv4 version");
        Equal(6, ipv6.IpVersion, "IPv6 version");
        Equal(LocalIpv4, ipv4.Source, "source address after IPv4 loopback header");
        Equal(LocalIpv6, ipv6.Source, "source address after IPv6 loopback header");
        Require(ipv4.IsHttp, "The loopback TCP request should be recognized.");
        Equal(TransportProtocol.IcmpV6, ipv6.Transport, "IPv6 loopback transport");
    }

    private static void DecodesRawIp()
    {
        PacketInfo ipv4 = Decode(Ipv4(1, Icmp(8)), RawIpLinkType);
        PacketInfo ipv6 = Decode(Ipv6(58, Icmp(128)), RawIpLinkType);
        Equal(4, ipv4.IpVersion, "raw IPv4 version");
        Equal(6, ipv6.IpVersion, "raw IPv6 version");
        Equal(TransportProtocol.Icmp, ipv4.Transport, "raw IPv4 transport");
        Equal(TransportProtocol.IcmpV6, ipv6.Transport, "raw IPv6 transport");
    }

    private static void HandlesLaterIpv4Fragment()
    {
        byte[] frame = Ethernet(0x0800, Ipv4(6, Tcp(ClientPort, WebPort, HttpRequest), fragmentField: 1));
        PacketInfo packet = Decode(frame);
        Equal(4, packet.IpVersion, "IP version");
        Equal<ushort?>(null, packet.SourcePort, "source port of non-first fragment");
        Equal<ushort?>(null, packet.DestinationPort, "destination port of non-first fragment");
        Require(!packet.IsHttp && TcpFlowKey.From(packet) is null, "A later fragment has no TCP header.");
    }

    private static void IgnoresEthernetPadding()
    {
        byte[] frame = [.. Ethernet(0x0800, Ipv4(6, Tcp(ClientPort, WebPort, []))), .. HttpRequest];
        PacketInfo packet = Decode(frame);
        Equal(TransportProtocol.Tcp, packet.Transport, "transport");
        Require(!packet.IsHttp, "Trailing bytes beyond the IP total length are not TCP payload.");
    }

    private static void HandlesTruncatedPrefixes()
    {
        (byte[] Frame, int LinkType)[] inputs =
        [
            (RequestFrame(), EthernetLinkType),
            (Ethernet(0x86dd, Ipv6(0, Ipv6HopByHop(58, Icmp(128))), vlan: true), EthernetLinkType),
            (Loopback(2, Ipv4(17, Udp(5000, 5001, [1, 2, 3]))), LoopbackLinkType),
        ];
        foreach ((byte[] frame, int linkType) in inputs)
        {
            for (int length = 0; length < frame.Length; length++)
            {
                PacketInfo packet = PacketDecoder.Decode(frame.AsSpan(0, length), linkType, Timestamp, frame.Length);
                Equal(length, packet.CapturedLength, $"captured length for link type {linkType}");
                Equal(frame.Length, packet.WireLength, $"wire length for link type {linkType}");
            }
        }
    }

    private static void HandlesUnknownLinkType()
    {
        PacketInfo packet = Decode(RequestFrame(), 65535);
        Equal(0, packet.IpVersion, "IP version");
        Equal(TransportProtocol.Other, packet.Transport, "transport");
        Require(!packet.IsHttp, "An unknown link type cannot be assumed to be Ethernet.");
    }

    private static void GroupsBothFlowDirections()
    {
        TcpFlowKey? outbound = TcpFlowKey.From(Decode(RequestFrame()));
        TcpFlowKey? inbound = TcpFlowKey.From(Decode(ResponseFrame()));
        Require(outbound.HasValue, "Expected a flow for the request.");
        Equal(outbound, inbound, "reversed flow key");
        Equal<TcpFlowKey?>(TcpFlowKey.Create(LocalIpv4, ClientPort, RemoteIpv4, WebPort), outbound, "flow key from endpoints");

        PacketInfo ipv6Outbound = Decode(Ethernet(0x86dd, Ipv6(6, Tcp(ClientPort, WebPort, []))));
        PacketInfo ipv6Inbound = Decode(Ethernet(0x86dd, Ipv6(6, Tcp(WebPort, ClientPort, []), reply: true)));
        TcpFlowKey? ipv6Flow = TcpFlowKey.From(ipv6Outbound);
        Require(ipv6Flow.HasValue, "Expected a flow for IPv6 TCP traffic.");
        Equal(ipv6Flow, TcpFlowKey.From(ipv6Inbound), "reversed IPv6 flow key");
    }

    private static void SeparatesDifferentFlows()
    {
        TcpFlowKey first = TcpFlowKey.Create(LocalIpv4, ClientPort, RemoteIpv4, WebPort);
        TcpFlowKey otherPort = TcpFlowKey.Create(LocalIpv4, ClientPort + 1, RemoteIpv4, WebPort);
        TcpFlowKey otherAddress = TcpFlowKey.Create(LocalIpv4, ClientPort, System.Net.IPAddress.Parse("198.51.100.31"), WebPort);
        Require(first != otherPort, "Changing one port must change the key.");
        Require(first != otherAddress, "Changing one address must change the key.");
    }

    private static void FiltersProtocols()
    {
        PacketInfo http = Decode(RequestFrame());
        PacketInfo udp = Decode(Ethernet(0x0800, Ipv4(17, Udp(5000, 5001, []))));
        PacketInfo icmp = Decode(Ethernet(0x0800, Ipv4(1, Icmp(8))));
        PacketInfo icmp6 = Decode(Ethernet(0x86dd, Ipv6(58, Icmp(128))));

        MatchesExactly(http, ProtocolFilter.All, ProtocolFilter.IPv4, ProtocolFilter.Tcp, ProtocolFilter.Http);
        MatchesExactly(udp, ProtocolFilter.All, ProtocolFilter.IPv4, ProtocolFilter.Udp);
        MatchesExactly(icmp, ProtocolFilter.All, ProtocolFilter.IPv4, ProtocolFilter.Icmp);
        MatchesExactly(icmp6, ProtocolFilter.All, ProtocolFilter.IPv6, ProtocolFilter.Icmp);
    }

    private static void MatchesExactly(PacketInfo packet, params ProtocolFilter[] expectedMatches)
    {
        foreach (ProtocolFilter filter in Enum.GetValues<ProtocolFilter>())
        {
            Equal(expectedMatches.Contains(filter), PacketFilters.Matches(packet, filter), $"{packet.Transport} matching {filter}");
        }
    }

    private static byte[] RequestFrame() => Ethernet(0x0800, Ipv4(6, Tcp(ClientPort, WebPort, HttpRequest)));

    private static byte[] ResponseFrame() => Ethernet(0x0800, Ipv4(6, Tcp(WebPort, ClientPort, HttpResponse), reply: true));

    private static PacketInfo Decode(byte[] frame, int linkType = EthernetLinkType) =>
        PacketDecoder.Decode(frame, linkType, Timestamp, frame.Length);

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static void Equal<T>(T expected, T actual, string description)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected {description} to be '{expected}', got '{actual}'.");
        }
    }
}
