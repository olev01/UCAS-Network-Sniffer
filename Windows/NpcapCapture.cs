using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ExperimentA.Windows;

internal sealed record CaptureAdapter(string Id, string Name)
{
    public override string ToString() => Name;
}

internal sealed class NpcapCapture : IDisposable
{
    private const int ErrorBufferSize = 256;
    private const int SnapshotLength = 262144;
    private const int BufferTimeoutMs = 50;
    private const uint PcapUtf8 = 1;
    private const uint UnknownNetmask = uint.MaxValue;
    private const string LoopbackAdapterId = @"\Device\NPF_Loopback";
    private static readonly Lazy<nint> NpcapLibrary = new(LoadNpcap);
    private readonly object _captureLock = new();
    private readonly CaptureHandle _handle;

    public int LinkType { get; }

    public static IReadOnlyList<CaptureAdapter> ListAdapters()
    {
        var error = new byte[ErrorBufferSize];
        if (Native.pcap_findalldevs(out nint head, error) != 0)
            throw new InvalidOperationException($"无法枚举抓包网卡。{ReadError(error)}");

        var adapters = new List<CaptureAdapter>();
        try
        {
            for (nint current = head; current != 0;)
            {
                var adapter = Marshal.PtrToStructure<NativeAdapter>(current);
                current = adapter.Next;
                string? id = Marshal.PtrToStringUTF8(adapter.Name);
                if (string.IsNullOrEmpty(id))
                    continue;

                if (id.Equals(LoopbackAdapterId, StringComparison.OrdinalIgnoreCase))
                {
                    adapters.Insert(0, new CaptureAdapter(id, "本机回环接口（Npcap）"));
                    continue;
                }

                string? description = Marshal.PtrToStringUTF8(adapter.Description);
                adapters.Add(new CaptureAdapter(id, string.IsNullOrWhiteSpace(description) ? id : description));
            }
        }
        finally
        {
            if (head != 0)
                Native.pcap_freealldevs(head);
        }
        return adapters;
    }

    public NpcapCapture(CaptureAdapter adapter, string? filter = null)
    {
        var error = new byte[ErrorBufferSize];
        nint handle = Native.pcap_open_live(adapter.Id, SnapshotLength, 0, BufferTimeoutMs, error);
        if (handle == 0)
            throw new InvalidOperationException($"无法打开网卡“{adapter.Name}”。{ReadError(error)}");

        _handle = new CaptureHandle(handle);
        try
        {
            if (!string.IsNullOrWhiteSpace(filter))
                ApplyFilter(filter);

            Array.Clear(error);
            if (Native.pcap_setnonblock(_handle, 1, error) != 0)
                throw new InvalidOperationException($"无法设置非阻塞抓包。{ReadError(error)}");

            LinkType = Native.pcap_datalink(_handle);
            if (LinkType < 0)
                throw new InvalidOperationException($"无法读取网卡的链路层类型。{GetCaptureError()}");
        }
        catch
        {
            _handle.Dispose();
            throw;
        }
    }

    public bool TryRead(out byte[] data, out DateTimeOffset timestamp, out int wireLength)
    {
        lock (_captureLock)
        {
            ObjectDisposedException.ThrowIf(_handle.IsClosed, this);
            int result = Native.pcap_next_ex(_handle, out nint headerPointer, out nint bytesPointer);
            if (result == 0)
            {
                data = [];
                timestamp = default;
                wireLength = 0;
                return false;
            }
            if (result != 1)
                throw new InvalidOperationException($"抓包读取失败（状态 {result}）。{GetCaptureError()}");
            if (headerPointer == 0)
                throw new InvalidOperationException("Npcap 返回了空的数据包头。");

            var header = Marshal.PtrToStructure<NativePacketHeader>(headerPointer);
            if (header.CapturedLength > SnapshotLength || header.CapturedLength > header.WireLength ||
                header.WireLength > int.MaxValue || header.Microseconds is < 0 or >= 1_000_000 ||
                (header.CapturedLength > 0 && bytesPointer == 0))
            {
                throw new InvalidOperationException("Npcap 返回的数据包头无效。");
            }

            data = new byte[(int)header.CapturedLength];
            if (data.Length > 0)
                Marshal.Copy(bytesPointer, data, 0, data.Length);
            timestamp = DateTimeOffset.FromUnixTimeSeconds(header.Seconds).AddTicks(header.Microseconds * 10L);
            wireLength = (int)header.WireLength;
            return true;
        }
    }

    public void Dispose()
    {
        lock (_captureLock)
            _handle.Dispose();
    }

    private string GetCaptureError() => Marshal.PtrToStringUTF8(Native.pcap_geterr(_handle)) ?? "";

    private void ApplyFilter(string expression)
    {
        if (Native.pcap_compile(_handle, out BpfProgram program, expression, 1, UnknownNetmask) != 0)
            throw new InvalidOperationException($"无法编译抓包过滤表达式。{GetCaptureError()}");

        try
        {
            if (Native.pcap_setfilter(_handle, ref program) != 0)
                throw new InvalidOperationException($"无法应用抓包过滤表达式。{GetCaptureError()}");
        }
        finally
        {
            Native.pcap_freecode(ref program);
        }
    }

    private static string ReadError(byte[] buffer)
    {
        int end = Array.IndexOf(buffer, (byte)0);
        return Encoding.UTF8.GetString(buffer, 0, end < 0 ? buffer.Length : end);
    }

    private static nint LoadNpcap()
    {
        string systemDirectory = Environment.SystemDirectory;
        string primaryPath = Path.Combine(systemDirectory, "Npcap", "wpcap.dll");
        string compatibilityPath = Path.Combine(systemDirectory, "wpcap.dll");
        const uint searchDllDirectory = 0x00000100;
        const uint searchSystem32 = 0x00000800;
        const uint searchFlags = searchDllDirectory | searchSystem32;

        nint library = Native.LoadLibraryEx(primaryPath, 0, searchFlags);
        if (library == 0)
            library = Native.LoadLibraryEx(compatibilityPath, 0, searchFlags);
        if (library == 0)
            throw new InvalidOperationException("无法加载 Npcap。请安装与 Windows 架构匹配的 Npcap 驱动后重试。");

        bool initialized = false;
        try
        {
            if (!NativeLibrary.TryGetExport(library, "pcap_init", out nint initAddress))
                throw new InvalidOperationException("系统中的抓包库版本过旧。请安装新版 Npcap 后重试。");

            var initialize = Marshal.GetDelegateForFunctionPointer<InitializeNpcap>(initAddress);
            var error = new byte[ErrorBufferSize];
            if (initialize(PcapUtf8, error) != 0)
                throw new InvalidOperationException($"Npcap 初始化失败。{ReadError(error)}");

            initialized = true;
            return library;
        }
        finally
        {
            if (!initialized)
                NativeLibrary.Free(library);
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int InitializeNpcap(uint options, [Out] byte[] error);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeAdapter
    {
        public nint Next;
        public nint Name;
        public nint Description;
        public nint Addresses;
        public uint Flags;
    }

    // Npcap's Windows timeval contains two 32-bit C longs, including on x64.
    [StructLayout(LayoutKind.Sequential)]
    private struct NativePacketHeader
    {
        public int Seconds;
        public int Microseconds;
        public uint CapturedLength;
        public uint WireLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BpfProgram
    {
        public uint InstructionCount;
        public nint Instructions;
    }

    private sealed class CaptureHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public CaptureHandle(nint pointer) : base(true) => SetHandle(pointer);

        protected override bool ReleaseHandle()
        {
            Native.pcap_close(handle);
            return true;
        }
    }

    private static class Native
    {
        private const string PcapLibraryName = "ExperimentA.Npcap";

        static Native()
        {
            NativeLibrary.SetDllImportResolver(typeof(NpcapCapture).Assembly, ResolveLibrary);
        }

        private static nint ResolveLibrary(string name, Assembly assembly, DllImportSearchPath? searchPath) =>
            name == PcapLibraryName ? NpcapLibrary.Value : 0;

        [DllImport("kernel32.dll", EntryPoint = "LoadLibraryExW", ExactSpelling = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint LoadLibraryEx(string path, nint file, uint flags);

        [DllImport(PcapLibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_findalldevs(out nint adapters, [Out] byte[] error);

        [DllImport(PcapLibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void pcap_freealldevs(nint adapters);

        [DllImport(PcapLibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern nint pcap_open_live([MarshalAs(UnmanagedType.LPUTF8Str)] string adapter,
            int snapshotLength, int promiscuous, int timeoutMs, [Out] byte[] error);

        [DllImport(PcapLibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_setnonblock(CaptureHandle capture, int nonBlocking, [Out] byte[] error);

        [DllImport(PcapLibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_compile(CaptureHandle capture, out BpfProgram program,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string expression, int optimize, uint netmask);

        [DllImport(PcapLibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_setfilter(CaptureHandle capture, ref BpfProgram program);

        [DllImport(PcapLibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void pcap_freecode(ref BpfProgram program);

        [DllImport(PcapLibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_datalink(CaptureHandle capture);

        [DllImport(PcapLibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_next_ex(CaptureHandle capture, out nint header, out nint data);

        [DllImport(PcapLibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern nint pcap_geterr(CaptureHandle capture);

        [DllImport(PcapLibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void pcap_close(nint capture);
    }
}
