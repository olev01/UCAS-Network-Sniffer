using System.Net;

namespace ExperimentA.Core;

internal readonly record struct TcpFlowKey(string First, string Second)
{
    internal static TcpFlowKey? From(PacketInfo packet)
    {
        if (packet.Transport == TransportProtocol.Tcp &&
            packet.Source is IPAddress source && packet.SourcePort is ushort sourcePort &&
            packet.Destination is IPAddress destination && packet.DestinationPort is ushort destinationPort)
        {
            return Create(source, sourcePort, destination, destinationPort);
        }

        return null;
    }

    internal static TcpFlowKey Create(IPAddress a, ushort aPort, IPAddress b, ushort bPort)
    {
        string first = Endpoint(a, aPort);
        string second = Endpoint(b, bPort);
        return string.CompareOrdinal(first, second) <= 0
            ? new TcpFlowKey(first, second)
            : new TcpFlowKey(second, first);
    }

    public override string ToString() => $"{First} ↔ {Second}";

    private static string Endpoint(IPAddress address, ushort port)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }
        // IP headers carry the addresses but no Windows interface scope IDs.
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            address = new IPAddress(address.GetAddressBytes());
        }
        return new IPEndPoint(address, port).ToString();
    }
}
