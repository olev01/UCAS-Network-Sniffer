using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace ExperimentA.Checks;

internal static class TestFrames
{
    public static readonly IPAddress LocalIpv4 = IPAddress.Parse("192.0.2.20");
    public static readonly IPAddress RemoteIpv4 = IPAddress.Parse("198.51.100.30");
    public static readonly IPAddress LocalIpv6 = IPAddress.Parse("2001:db8::20");
    public static readonly IPAddress RemoteIpv6 = IPAddress.Parse("2001:db8::30");

    public static readonly byte[] HttpRequest = Encoding.ASCII.GetBytes(
        "GET /lab HTTP/1.1\r\nHost: example.test\r\n\r\n");

    public static readonly byte[] HttpResponse = Encoding.ASCII.GetBytes(
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

    public static byte[] Ethernet(ushort type, byte[] payload, bool vlan = false)
    {
        int headerLength = vlan ? 18 : 14;
        var frame = new byte[headerLength + payload.Length];
        frame[0] = 0x02;
        frame[5] = 0x01;
        frame[6] = 0x02;
        frame[11] = 0x02;
        if (vlan)
        {
            WriteUInt16(frame, 12, 0x8100);
            WriteUInt16(frame, 14, 7);
        }

        WriteUInt16(frame, headerLength - 2, type);
        payload.CopyTo(frame, headerLength);
        return frame;
    }

    public static byte[] Loopback(uint family, byte[] packet)
    {
        // The Windows DLT_NULL header contains the host-endian address family.
        var frame = new byte[4 + packet.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(frame, family);
        packet.CopyTo(frame, 4);
        return frame;
    }

    public static byte[] Ipv4(byte protocol, byte[] payload, bool reply = false, ushort fragmentField = 0)
    {
        const int headerLength = 20;
        var packet = new byte[headerLength + payload.Length];
        packet[0] = 0x45;
        WriteUInt16(packet, 2, checked((ushort)packet.Length));
        WriteUInt16(packet, 6, fragmentField);
        packet[8] = 64;
        packet[9] = protocol;
        (reply ? RemoteIpv4 : LocalIpv4).GetAddressBytes().CopyTo(packet, 12);
        (reply ? LocalIpv4 : RemoteIpv4).GetAddressBytes().CopyTo(packet, 16);
        payload.CopyTo(packet, headerLength);
        return packet;
    }

    public static byte[] Ipv6(byte nextHeader, byte[] payload, bool reply = false)
    {
        const int headerLength = 40;
        var packet = new byte[headerLength + payload.Length];
        packet[0] = 0x60;
        WriteUInt16(packet, 4, checked((ushort)payload.Length));
        packet[6] = nextHeader;
        packet[7] = 64;
        (reply ? RemoteIpv6 : LocalIpv6).GetAddressBytes().CopyTo(packet, 8);
        (reply ? LocalIpv6 : RemoteIpv6).GetAddressBytes().CopyTo(packet, 24);
        payload.CopyTo(packet, headerLength);
        return packet;
    }

    public static byte[] Ipv6HopByHop(byte nextHeader, byte[] payload)
    {
        const int extensionLength = 8;
        var extension = new byte[extensionLength + payload.Length];
        extension[0] = nextHeader;
        // A zero length field encodes an eight-byte header. The options are Pad1.
        payload.CopyTo(extension, extensionLength);
        return extension;
    }

    public static byte[] Tcp(ushort source, ushort destination, byte[] payload)
    {
        const int headerLength = 20;
        var segment = new byte[headerLength + payload.Length];
        WriteUInt16(segment, 0, source);
        WriteUInt16(segment, 2, destination);
        segment[12] = 0x50;
        segment[13] = 0x18;
        WriteUInt16(segment, 14, 4096);
        payload.CopyTo(segment, headerLength);
        return segment;
    }

    public static byte[] Udp(ushort source, ushort destination, byte[] payload)
    {
        const int headerLength = 8;
        var datagram = new byte[headerLength + payload.Length];
        WriteUInt16(datagram, 0, source);
        WriteUInt16(datagram, 2, destination);
        WriteUInt16(datagram, 4, checked((ushort)datagram.Length));
        payload.CopyTo(datagram, headerLength);
        return datagram;
    }

    public static byte[] Icmp(byte type) => [type, 0, 0, 0, 0x12, 0x34, 0, 1];

    private static void WriteUInt16(byte[] data, int offset, ushort value) =>
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(offset), value);
}
