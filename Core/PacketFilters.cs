namespace ExperimentA.Core;

internal enum ProtocolFilter
{
    All,
    IPv4,
    IPv6,
    Tcp,
    Udp,
    Icmp,
    Http
}

internal static class PacketFilters
{
    internal static bool Matches(PacketInfo packet, ProtocolFilter filter) => filter switch
    {
        ProtocolFilter.All => true,
        ProtocolFilter.IPv4 => packet.IpVersion == 4,
        ProtocolFilter.IPv6 => packet.IpVersion == 6,
        ProtocolFilter.Tcp => packet.Transport == TransportProtocol.Tcp,
        ProtocolFilter.Udp => packet.Transport == TransportProtocol.Udp,
        ProtocolFilter.Icmp => packet.Transport is TransportProtocol.Icmp or TransportProtocol.IcmpV6,
        ProtocolFilter.Http => packet.IsHttp,
        _ => false
    };
}
