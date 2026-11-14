using System;
using System.Net;
using System.Text;
using static System.Buffers.Binary.BinaryPrimitives;

namespace ExperimentA.Core;

internal sealed class PacketDecoder
{
    private const int DltNull = 0;
    private const int DltEthernet = 1;
    private const int DltRaw = 12;
    private const int LinkTypeRaw = 101;
    private const int DltLoop = 108;
    private const int DltIPv4 = 228;
    private const int DltIPv6 = 229;
    private const int EtherTypeIPv4 = 0x0800;
    private const int EtherTypeIPv6 = 0x86DD;
    private const int MaximumHttpStartLine = 4096;

    private readonly StringBuilder _details = new(256);
    private string _summary = "其他";
    private IPAddress? _source;
    private IPAddress? _destination;
    private ushort? _sourcePort;
    private ushort? _destinationPort;
    private int _ipVersion;
    private TransportProtocol _transport;
    private bool _isHttp;

    private PacketDecoder()
    {
    }

    internal static PacketInfo Decode(ReadOnlySpan<byte> data, int linkType,
        DateTimeOffset timestamp, int wireLength)
    {
        var decoder = new PacketDecoder();
        decoder._details.AppendLine($"捕获长度 {data.Length} 字节，原始长度 {wireLength} 字节");
        decoder.DecodeLink(data, linkType);

        return new PacketInfo
        {
            Timestamp = timestamp,
            WireLength = wireLength,
            CapturedLength = data.Length,
            Source = decoder._source,
            Destination = decoder._destination,
            SourcePort = decoder._sourcePort,
            DestinationPort = decoder._destinationPort,
            IpVersion = decoder._ipVersion,
            Transport = decoder._transport,
            IsHttp = decoder._isHttp,
            Summary = decoder._summary,
            Details = decoder._details.ToString()
        };
    }

    private void DecodeLink(ReadOnlySpan<byte> frame, int linkType)
    {
        switch (linkType)
        {
            case DltEthernet:
                DecodeEthernet(frame);
                break;
            case DltNull:
            case DltLoop:
                DecodeLoopback(frame, linkType);
                break;
            case DltRaw:
            case LinkTypeRaw:
                _details.AppendLine("链路层：原始 IP");
                DecodeNetwork(frame, frame.IsEmpty ? 0 : frame[0] >> 4);
                break;
            case DltIPv4:
            case DltIPv6:
                _details.AppendLine("链路层：原始 IP");
                DecodeNetwork(frame, linkType == DltIPv4 ? 4 : 6);
                break;
            default:
                _details.AppendLine($"未支持的链路层类型 {linkType}");
                break;
        }
    }

    private void DecodeEthernet(ReadOnlySpan<byte> frame)
    {
        const int ethernetHeaderLength = 14;
        if (frame.Length < ethernetHeaderLength)
        {
            _details.AppendLine("以太网头部不完整。");
            return;
        }

        _details.AppendLine($"以太网：源 MAC {Convert.ToHexString(frame.Slice(6, 6))}，"
            + $"目的 MAC {Convert.ToHexString(frame[..6])}");

        var offset = ethernetHeaderLength;
        var etherType = ReadUInt16BigEndian(frame[12..]);
        while (etherType is 0x8100 or 0x88A8 or 0x9100)
        {
            if (frame.Length - offset < 4)
            {
                _details.AppendLine("VLAN 标签不完整。");
                return;
            }

            var tag = ReadUInt16BigEndian(frame[offset..]);
            _details.AppendLine($"VLAN：ID {tag & 0x0FFF}，优先级 {tag >> 13}");
            etherType = ReadUInt16BigEndian(frame[(offset + 2)..]);
            offset += 4;
        }

        _details.AppendLine($"以太网类型 0x{etherType:X4}");
        switch (etherType)
        {
            case EtherTypeIPv4:
                DecodeIPv4(frame[offset..]);
                break;
            case EtherTypeIPv6:
                DecodeIPv6(frame[offset..]);
                break;
            case 0x0806:
                _summary = "ARP";
                break;
        }
    }

    private void DecodeLoopback(ReadOnlySpan<byte> frame, int linkType)
    {
        const int loopbackHeaderLength = 4;
        if (frame.Length < loopbackHeaderLength)
        {
            _details.AppendLine("回环头部不完整。");
            return;
        }

        var family = ReadUInt32BigEndian(frame);
        if (linkType == DltNull && family > byte.MaxValue)
        {
            family = ReadUInt32LittleEndian(frame);
        }

        _details.AppendLine($"回环：地址族 {family}");
        var version = family switch
        {
            2 => 4,
            24 or 28 or 30 => 6,
            _ => 0
        };
        DecodeNetwork(frame[loopbackHeaderLength..], version);
    }

    private void DecodeNetwork(ReadOnlySpan<byte> packet, int version)
    {
        switch (version)
        {
            case 4:
                DecodeIPv4(packet);
                break;
            case 6:
                DecodeIPv6(packet);
                break;
            default:
                _details.AppendLine("未识别 IP 版本。");
                break;
        }
    }

    private void DecodeIPv4(ReadOnlySpan<byte> packet)
    {
        const int minimumHeaderLength = 20;
        if (packet.Length < minimumHeaderLength || packet[0] >> 4 != 4)
        {
            _details.AppendLine("IPv4 头部无效或不完整。");
            return;
        }

        var headerLength = (packet[0] & 0x0F) * 4;
        var totalLength = ReadUInt16BigEndian(packet[2..]);
        if (headerLength < minimumHeaderLength || headerLength > packet.Length
            || totalLength < headerLength)
        {
            _details.AppendLine("IPv4 头部长度或总长度无效。");
            return;
        }

        _summary = "IPv4";
        _ipVersion = 4;
        _source = new IPAddress(packet.Slice(12, 4));
        _destination = new IPAddress(packet.Slice(16, 4));
        _details.AppendLine($"IPv4：{_source} → {_destination}");
        _details.AppendLine($"TTL {packet[8]}，协议号 {packet[9]}，"
            + $"总长度 {totalLength}，头部长度 {headerLength}");

        var fragmentField = ReadUInt16BigEndian(packet[6..]);
        var fragmentOffset = (fragmentField & 0x1FFF) * 8;
        var moreFragments = (fragmentField & 0x2000) != 0;
        if (moreFragments || fragmentOffset != 0)
        {
            _details.AppendLine($"IPv4 分片：偏移 {fragmentOffset} 字节，后续分片 {YesNo(moreFragments)}");
        }

        var capturedLength = GetCapturedLength(packet.Length, totalLength);
        DecodeTransport(packet[headerLength..capturedLength], packet[9], fragmentOffset != 0,
            moreFragments, totalLength - headerLength);
    }

    private void DecodeIPv6(ReadOnlySpan<byte> packet)
    {
        const int headerLength = 40;
        if (packet.Length < headerLength || packet[0] >> 4 != 6)
        {
            _details.AppendLine("IPv6 头部无效或不完整。");
            return;
        }

        _summary = "IPv6";
        _ipVersion = 6;
        _source = new IPAddress(packet.Slice(8, 16));
        _destination = new IPAddress(packet.Slice(24, 16));
        var payloadLength = ReadUInt16BigEndian(packet[4..]);
        _details.AppendLine($"IPv6：{_source} → {_destination}");
        _details.AppendLine($"跳数限制 {packet[7]}，后继头部 {packet[6]}，载荷长度 {payloadLength}");

        var nextHeader = packet[6];
        if (payloadLength == 0)
        {
            if (nextHeader == 0 && packet.Length > headerLength)
            {
                _details.AppendLine("未解析 IPv6 巨型载荷。");
            }
            return;
        }

        var totalLength = headerLength + payloadLength;
        var capturedLength = GetCapturedLength(packet.Length, totalLength);
        var payload = packet[headerLength..capturedLength];
        var remainingLength = (int)payloadLength;
        var nonInitialFragment = false;
        var moreFragments = false;
        while (nextHeader is 0 or 43 or 44 or 51 or 60)
        {
            if (payload.Length < 2)
            {
                _details.AppendLine("IPv6 扩展头部不完整。");
                return;
            }

            var extensionLength = nextHeader switch
            {
                44 => 8,
                51 => (payload[1] + 2) * 4,
                _ => (payload[1] + 1) * 8
            };
            if (extensionLength > payload.Length || (nextHeader == 51 && extensionLength < 12))
            {
                _details.AppendLine("IPv6 扩展头部长度无效或捕获不完整。");
                return;
            }

            _details.AppendLine($"IPv6 扩展头部 {nextHeader}，长度 {extensionLength}");
            if (nextHeader == 44)
            {
                var fragmentField = ReadUInt16BigEndian(payload[2..]);
                var fragmentOffset = fragmentField & 0xFFF8;
                moreFragments = (fragmentField & 1) != 0;
                nonInitialFragment = fragmentOffset != 0;
                _details.AppendLine($"IPv6 分片：偏移 {fragmentOffset} 字节，后续分片 {YesNo(moreFragments)}");
            }

            nextHeader = payload[0];
            payload = payload[extensionLength..];
            remainingLength -= extensionLength;
            if (nonInitialFragment)
            {
                break;
            }
        }

        DecodeTransport(payload, nextHeader, nonInitialFragment, moreFragments, remainingLength);
    }

    private void DecodeTransport(ReadOnlySpan<byte> payload, byte protocol, bool nonInitialFragment,
        bool moreFragments, int declaredLength)
    {
        _transport = protocol switch
        {
            6 => TransportProtocol.Tcp,
            17 => TransportProtocol.Udp,
            1 when _ipVersion == 4 => TransportProtocol.Icmp,
            58 when _ipVersion == 6 => TransportProtocol.IcmpV6,
            _ => TransportProtocol.Other
        };

        if (_transport == TransportProtocol.Other)
        {
            return;
        }

        _summary = _transport switch
        {
            TransportProtocol.Tcp => "TCP",
            TransportProtocol.Udp => "UDP",
            TransportProtocol.Icmp => "ICMP",
            _ => "ICMPv6"
        };
        if (nonInitialFragment)
        {
            _summary += " 分片";
            return;
        }

        switch (_transport)
        {
            case TransportProtocol.Tcp:
                DecodeTcp(payload);
                break;
            case TransportProtocol.Udp:
                DecodeUdp(payload, moreFragments, declaredLength);
                break;
            default:
                DecodeIcmp(payload);
                break;
        }
    }

    private void DecodeTcp(ReadOnlySpan<byte> segment)
    {
        const int minimumHeaderLength = 20;
        if (segment.Length < minimumHeaderLength)
        {
            _details.AppendLine("TCP 头部不完整。");
            return;
        }

        var headerLength = (segment[12] >> 4) * 4;
        if (headerLength < minimumHeaderLength || headerLength > segment.Length)
        {
            _details.AppendLine("TCP 头部长度无效或捕获不完整。");
            return;
        }

        _sourcePort = ReadUInt16BigEndian(segment);
        _destinationPort = ReadUInt16BigEndian(segment[2..]);
        var flags = FormatTcpFlags(segment[13]);
        var payload = segment[headerLength..];
        _summary = $"TCP {flags}";
        _details.AppendLine($"TCP：源端口 {_sourcePort}，目的端口 {_destinationPort}");
        _details.AppendLine($"标志 {flags}，序号 {ReadUInt32BigEndian(segment[4..])}，"
            + $"确认号 {ReadUInt32BigEndian(segment[8..])}，窗口 {ReadUInt16BigEndian(segment[14..])}");
        _details.AppendLine($"TCP 头部长度 {headerLength}，已捕获 TCP 载荷长度 {payload.Length}");

        if (IsHttpStart(payload))
        {
            _isHttp = true;
            _summary = "HTTP/1.x";
            _details.AppendLine("应用层：识别到明文 HTTP/1.x 起始行。");
        }
    }

    private void DecodeUdp(ReadOnlySpan<byte> datagram, bool moreFragments, int declaredLength)
    {
        const int headerLength = 8;
        if (datagram.Length < headerLength)
        {
            _details.AppendLine("UDP 头部不完整。");
            return;
        }

        var length = ReadUInt16BigEndian(datagram[4..]);
        if (length < headerLength || (!moreFragments && length > declaredLength))
        {
            _details.AppendLine("UDP 长度无效。");
            return;
        }

        _sourcePort = ReadUInt16BigEndian(datagram);
        _destinationPort = ReadUInt16BigEndian(datagram[2..]);
        _details.AppendLine($"UDP：源端口 {_sourcePort}，目的端口 {_destinationPort}，总长度 {length}");
    }

    private void DecodeIcmp(ReadOnlySpan<byte> message)
    {
        if (message.Length < 4)
        {
            _details.AppendLine($"{_summary} 头部不完整。");
            return;
        }

        _details.AppendLine($"{_summary}：类型 {message[0]}，代码 {message[1]}，"
            + $"校验和 0x{ReadUInt16BigEndian(message[2..]):X4}");
    }

    private int GetCapturedLength(int capturedLength, int declaredLength)
    {
        if (capturedLength < declaredLength)
        {
            _details.AppendLine($"IP 捕获不完整：已捕获 {capturedLength}，头部声明 {declaredLength} 字节。");
        }
        return Math.Min(capturedLength, declaredLength);
    }

    private static string YesNo(bool value) => value ? "是" : "否";

    private static string FormatTcpFlags(byte flags)
    {
        if (flags == 0)
        {
            return "无标志";
        }

        var labels = new StringBuilder(32);
        if ((flags & 0x02) != 0) labels.Append("SYN ");
        if ((flags & 0x10) != 0) labels.Append("ACK ");
        if ((flags & 0x01) != 0) labels.Append("FIN ");
        if ((flags & 0x04) != 0) labels.Append("RST ");
        if ((flags & 0x08) != 0) labels.Append("PSH ");
        if ((flags & 0x20) != 0) labels.Append("URG ");
        if ((flags & 0x40) != 0) labels.Append("ECE ");
        if ((flags & 0x80) != 0) labels.Append("CWR ");
        return labels.ToString(0, labels.Length - 1);
    }

    private static bool IsHttpStart(ReadOnlySpan<byte> payload)
    {
        var lineEnd = payload[..Math.Min(payload.Length, MaximumHttpStartLine)].IndexOf("\r\n"u8);
        if (lineEnd < 0)
        {
            return false;
        }

        var line = payload[..lineEnd];
        if (line.StartsWith("HTTP/"u8))
        {
            return line.Length >= 13 && IsHttpVersion(line[..8]) && line[8] == (byte)' '
                && line[9] is >= (byte)'1' and <= (byte)'5' && IsDigit(line[10])
                && IsDigit(line[11]) && line[12] == (byte)' ';
        }

        var methodEnd = line.IndexOf((byte)' ');
        if (methodEnd < 0 || !IsHttpMethod(line[..methodEnd]))
        {
            return false;
        }

        var targetAndVersion = line[(methodEnd + 1)..];
        var targetEnd = targetAndVersion.IndexOf((byte)' ');
        if (targetEnd < 1 || !IsHttpVersion(targetAndVersion[(targetEnd + 1)..]))
        {
            return false;
        }

        foreach (var character in targetAndVersion[..targetEnd])
        {
            if (character is < 0x21 or > 0x7E)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsHttpVersion(ReadOnlySpan<byte> value) =>
        value.SequenceEqual("HTTP/1.0"u8) || value.SequenceEqual("HTTP/1.1"u8);

    private static bool IsDigit(byte value) => value is >= (byte)'0' and <= (byte)'9';

    private static bool IsHttpMethod(ReadOnlySpan<byte> value) =>
        value.SequenceEqual("GET"u8) || value.SequenceEqual("HEAD"u8) || value.SequenceEqual("POST"u8)
        || value.SequenceEqual("PUT"u8) || value.SequenceEqual("DELETE"u8) || value.SequenceEqual("CONNECT"u8)
        || value.SequenceEqual("OPTIONS"u8) || value.SequenceEqual("TRACE"u8) || value.SequenceEqual("PATCH"u8);
}
