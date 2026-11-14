using System;
using System.Net;

namespace ExperimentA.Core;

internal enum TransportProtocol
{
    Other,
    Tcp,
    Udp,
    Icmp,
    IcmpV6
}

internal sealed class PacketInfo
{
    internal required DateTimeOffset Timestamp { get; init; }
    internal required int WireLength { get; init; }
    internal required int CapturedLength { get; init; }
    internal IPAddress? Source { get; init; }
    internal IPAddress? Destination { get; init; }
    internal ushort? SourcePort { get; init; }
    internal ushort? DestinationPort { get; init; }
    internal int IpVersion { get; init; }
    internal TransportProtocol Transport { get; init; }
    internal bool IsHttp { get; init; }
    internal required string Summary { get; init; }
    internal required string Details { get; init; }
}
