using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using ExperimentA.Core;

namespace ExperimentA.Windows;

internal readonly record struct ProcessOwner(int Id, string Name)
{
    public override string ToString() => string.IsNullOrEmpty(Name) ? $"PID {Id}" : $"{Name} ({Id})";
}

internal sealed class TcpProcessLookup
{
    private const int OwnerPidConnections = 4;
    private const uint InsufficientBuffer = 122;
    private Dictionary<TcpFlowKey, ProcessOwner[]> snapshot = [];
    private long refreshAt;

    internal string? Error { get; private set; }

    internal ProcessOwner[] Find(TcpFlowKey? key)
    {
        if (key is null)
        {
            return [];
        }

        RefreshIfNeeded();
        return snapshot.TryGetValue(key.Value, out var owners) ? owners : [];
    }

    private void RefreshIfNeeded()
    {
        long now = Environment.TickCount64;
        if (now < refreshAt)
        {
            return;
        }
        refreshAt = now + 600;
        var collected = new Dictionary<TcpFlowKey, HashSet<int>>();
        var errors = new List<string>();
        foreach (int family in new[] { 2, 23 })
        {
            try
            {
                ReadFamily(family, collected);
            }
            catch (Win32Exception error)
            {
                errors.Add($"IPv{(family == 2 ? 4 : 6)} {error.NativeErrorCode}");
            }
        }

        Error = errors.Count > 0 ? $"连接表读取失败（{string.Join("、", errors)}）" : null;
        var names = new Dictionary<int, ProcessOwner>();
        var next = new Dictionary<TcpFlowKey, ProcessOwner[]>(collected.Count);
        foreach (var (key, ids) in collected)
        {
            var owners = new ProcessOwner[ids.Count];
            int index = 0;
            foreach (int id in ids)
            {
                if (!names.TryGetValue(id, out var owner))
                {
                    owner = new ProcessOwner(id, ResolveName(id));
                    names.Add(id, owner);
                }
                owners[index++] = owner;
            }
            Array.Sort(owners, (a, b) => a.Id.CompareTo(b.Id));
            next.Add(key, owners);
        }
        snapshot = next;
    }

    private static void ReadFamily(int family, Dictionary<TcpFlowKey, HashSet<int>> result)
    {
        uint size = 0;
        uint status = GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, OwnerPidConnections, 0);
        for (int attempt = 0; status == InsufficientBuffer && attempt < 4; attempt++)
        {
            byte[] bytes = new byte[checked((int)size)];
            var pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                status = GetExtendedTcpTable(pinned.AddrOfPinnedObject(), ref size, false, family, OwnerPidConnections, 0);
            }
            finally
            {
                pinned.Free();
            }
            if (status == 0 && bytes.Length >= 4)
            {
                ParseRows(bytes, family == 2, result);
                return;
            }
        }
        if (status != 0)
        {
            throw new Win32Exception((int)status);
        }
    }

    private static void ParseRows(ReadOnlySpan<byte> bytes, bool ipv4, Dictionary<TcpFlowKey, HashSet<int>> result)
    {
        int rowSize = ipv4 ? 24 : 56;
        int rowCount = Math.Min(BinaryPrimitives.ReadInt32LittleEndian(bytes), (bytes.Length - 4) / rowSize);
        for (int i = 0; i < rowCount; i++)
        {
            var row = bytes.Slice(4 + i * rowSize, rowSize);
            var local = new IPAddress(ipv4 ? row[4..8] : row[..16]);
            var remote = new IPAddress(ipv4 ? row[12..16] : row[24..40]);
            ushort localPort = BinaryPrimitives.ReadUInt16BigEndian(ipv4 ? row[8..10] : row[20..22]);
            ushort remotePort = BinaryPrimitives.ReadUInt16BigEndian(ipv4 ? row[16..18] : row[44..46]);
            int owner = BinaryPrimitives.ReadInt32LittleEndian(row[^4..]);
            if (owner <= 0 || localPort == 0 || remotePort == 0)
            {
                continue;
            }

            var key = TcpFlowKey.Create(local, localPort, remote, remotePort);
            if (!result.TryGetValue(key, out var ids))
            {
                ids = [];
                result.Add(key, ids);
            }
            ids.Add(owner);
        }
    }

    private static string ResolveName(int id)
    {
        try
        {
            using var process = Process.GetProcessById(id);
            return process.ProcessName;
        }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException or Win32Exception)
        {
            return "";
        }
    }

    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedTcpTable(
        IntPtr table, ref uint size, [MarshalAs(UnmanagedType.Bool)] bool order,
        int family, int tableClass, uint reserved);
}
