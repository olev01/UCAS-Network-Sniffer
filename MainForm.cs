using System.Collections.Concurrent;
using System.Text.Json;
using ExperimentA.Core;
using ExperimentA.Windows;

namespace ExperimentA;

internal sealed class MainForm : Form
{
    private const int HistoryLimit = 6_000;
    private const int PendingLimit = 2_000;
    private readonly ComboBox adapters = new() { Width = 355, DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly Button refresh = new() { Text = "刷新", AutoSize = true };
    private readonly Button start = new() { Text = "开始抓包", AutoSize = true };
    private readonly Button stop = new() { Text = "停止", AutoSize = true, Enabled = false };
    private readonly Button clear = new() { Text = "清空", AutoSize = true };
    private readonly ComboBox protocol = new() { Width = 112, DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly Button followFlow = new() { Text = "追踪 TCP 流", AutoSize = true, Enabled = false };
    private readonly ComboBox owner = new() { Width = 180, DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly Button reset = new() { Text = "重置筛选", AutoSize = true };
    private readonly Label selection = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true };
    private readonly ToolStripStatusLabel status = new() { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
    private readonly ToolStripStatusLabel counts = new();
    private readonly DataGridView grid = new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false,
        AllowUserToDeleteRows = false, RowHeadersVisible = false, MultiSelect = false,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect, VirtualMode = true,
        BackgroundColor = Color.White, BorderStyle = BorderStyle.None, AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.None
    };
    private readonly RichTextBox detail = new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, BackColor = Color.White, WordWrap = false, BorderStyle = BorderStyle.None
    };
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 125 };
    private readonly ConcurrentQueue<(PacketInfo Packet, ProcessOwner[] Owners)> pending = new();
    private readonly List<ObservedPacket> history = [];
    private readonly List<ObservedPacket> visible = [];
    private readonly Dictionary<int, ProcessOwner> knownOwners = [];
    private CancellationTokenSource? cancellation;
    private Task? captureTask;
    private string? captureError;
    private string? ownerError;
    private volatile bool opened;
    private bool closing;
    private int pendingCount;
    private int skipped;
    private long received;
    private long nextNumber;
    private TcpFlowKey? flow;
    private string? demoCaptureFilter;
    internal int DemoExitCode { get; private set; }
    private readonly record struct ObservedPacket(long Number, PacketInfo Packet, TcpFlowKey? Flow, ProcessOwner[] Owners);
    private sealed record ProtocolChoice(string Name, ProtocolFilter Value)
    {
        public override string ToString() => Name;
    }
    private sealed record OwnerChoice(string Name, int? Id)
    {
        public override string ToString() => Name;
    }

    internal MainForm()
    {
        Text = "NetScope · 网络嗅探器";
        Font = new Font("Microsoft YaHei UI", 9F);
        BackColor = Color.FromArgb(245, 247, 251);
        ForeColor = Color.FromArgb(25, 39, 58);
        MinimumSize = new Size(890, 620);
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(1120, 730);
        AutoScaleMode = AutoScaleMode.Font;

        var title = new Label
        {
            Text = "NetScope  /  网络嗅探器", Dock = DockStyle.Fill,
            Font = new Font(Font.FontFamily, 17F, FontStyle.Bold), TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = Color.FromArgb(18, 50, 87)
        };
        var captureBar = MakeBar();
        captureBar.Controls.AddRange([Caption("抓包接口"), adapters, refresh, start, stop, clear]);
        var filterBar = MakeBar();
        filterBar.Controls.AddRange([Caption("协议"), protocol, Caption("本机进程"), owner, followFlow, reset]);

        var split = new SplitContainer
        {
            Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterWidth = 7,
            FixedPanel = FixedPanel.Panel2
        };
        split.Panel1.Controls.Add(grid);
        var detailPanel = new TableLayoutPanel
        {
            BackColor = Color.White, ColumnCount = 1, RowCount = 2, Dock = DockStyle.Fill,
            Padding = new Padding(12, 5, 12, 4)
        };
        detailPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        detailPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        detail.Font = new Font(Font.FontFamily, 9.5F);
        detailPanel.Controls.Add(new Label
        {
            Text = "数据包详情", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font(Font.FontFamily, 10F, FontStyle.Bold)
        });
        detailPanel.Controls.Add(detail);
        split.Panel2.Controls.Add(detailPanel);

        var strip = new StatusStrip { Dock = DockStyle.Fill, SizingGrip = false, BackColor = BackColor };
        strip.Items.AddRange([status, counts]);
        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6, Padding = new Padding(16, 4, 16, 4)
        };
        foreach (int height in new[] { 48, 38, 38, 25 })
        {
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, height));
        }
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 29));
        layout.Controls.Add(title);
        layout.Controls.Add(captureBar);
        layout.Controls.Add(filterBar);
        layout.Controls.Add(selection);
        layout.Controls.Add(split);
        layout.Controls.Add(strip);
        Controls.Add(layout);

        SetupGrid();
        protocol.Items.AddRange([
            new ProtocolChoice("全部", ProtocolFilter.All),
            new ProtocolChoice("HTTP", ProtocolFilter.Http),
            new ProtocolChoice("TCP", ProtocolFilter.Tcp),
            new ProtocolChoice("UDP", ProtocolFilter.Udp),
            new ProtocolChoice("IPv4", ProtocolFilter.IPv4),
            new ProtocolChoice("IPv6", ProtocolFilter.IPv6),
            new ProtocolChoice("ICMP / v6", ProtocolFilter.Icmp)]);
        protocol.SelectedIndex = 0;
        owner.Items.Add(new OwnerChoice("所有进程", null));
        owner.SelectedIndex = 0;

        Shown += (_, _) =>
        {
            split.Panel1MinSize = 175;
            split.Panel2MinSize = 125;
            split.SplitterDistance = Math.Max(175, split.Height - 180);
            RefreshAdapters();
            Rebuild();
            timer.Start();
        };
        refresh.Click += (_, _) => RefreshAdapters();
        adapters.SelectedIndexChanged += (_, _) => start.Enabled = captureTask is null && adapters.SelectedItem is CaptureAdapter;
        start.Click += (_, _) => BeginCapture();
        stop.Click += (_, _) => RequestStop();
        clear.Click += (_, _) => ClearHistory();
        protocol.SelectedIndexChanged += (_, _) => Rebuild();
        owner.SelectedIndexChanged += (_, _) => Rebuild();
        followFlow.Click += (_, _) => SelectFlow();
        reset.Click += (_, _) =>
        {
            flow = null;
            protocol.SelectedIndex = 0;
            owner.SelectedIndex = 0;
            Rebuild();
        };
        timer.Tick += (_, _) => OnTick();
        FormClosing += (_, e) =>
        {
            if (captureTask is { IsCompleted: false })
            {
                e.Cancel = true;
                closing = true;
                RequestStop();
            }
            else
            {
                timer.Dispose();
                cancellation?.Dispose();
            }
        };
    }

    private static FlowLayoutPanel MakeBar() => new() { Dock = DockStyle.Fill, WrapContents = false };

    private static Label Caption(string label) => new()
    {
        Text = label, AutoSize = true, Margin = new Padding(5, 8, 3, 0)
    };

    private void SetupGrid()
    {
        grid.EnableHeadersVisualStyles = false;
        grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(227, 237, 250);
        grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(18, 50, 87);
        grid.ColumnHeadersHeight = 32;
        grid.RowTemplate.Height = 26;
        grid.GridColor = Color.FromArgb(230, 236, 243);
        grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(248, 250, 253);
        grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(29, 86, 146);
        AddColumn("序号", 60);
        AddColumn("时间", 105);
        AddColumn("源端点", 154);
        AddColumn("目的端点", 154);
        AddColumn("协议", 74);
        AddColumn("字节", 60);
        AddColumn("本机进程", 155);
        var summary = AddColumn("摘要", 110);
        summary.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
        grid.CellValueNeeded += (_, e) =>
        {
            if (e.RowIndex < 0 || e.RowIndex >= visible.Count)
            {
                return;
            }
            var row = visible[e.RowIndex];
            var packet = row.Packet;
            e.Value = e.ColumnIndex switch
            {
                0 => row.Number,
                1 => packet.Timestamp.ToLocalTime().ToString("HH:mm:ss.fff"),
                2 => FormatEndpoint(packet.Source, packet.SourcePort),
                3 => FormatEndpoint(packet.Destination, packet.DestinationPort),
                4 => ProtocolName(packet),
                5 => packet.WireLength,
                6 => string.Join("、", row.Owners.Select(p => p.ToString())),
                7 => packet.Summary,
                _ => null
            };
        };
        grid.SelectionChanged += (_, _) => ShowDetails();
    }

    private DataGridViewTextBoxColumn AddColumn(string caption, int width)
    {
        var column = new DataGridViewTextBoxColumn
        {
            HeaderText = caption, Width = width, SortMode = DataGridViewColumnSortMode.NotSortable
        };
        grid.Columns.Add(column);
        return column;
    }

    private static string FormatEndpoint(System.Net.IPAddress? address, ushort? port) =>
        address is null ? "—" : port is ushort value ? new System.Net.IPEndPoint(address, value).ToString() : address.ToString();

    private static string ProtocolName(PacketInfo packet) => packet.IsHttp ? "HTTP" : packet.Transport switch
    {
        TransportProtocol.Tcp => "TCP",
        TransportProtocol.Udp => "UDP",
        TransportProtocol.Icmp => "ICMP",
        TransportProtocol.IcmpV6 => "ICMPv6",
        _ => packet.IpVersion > 0 ? $"IPv{packet.IpVersion}" : "其他"
    };

    private void RefreshAdapters()
    {
        string? previous = (adapters.SelectedItem as CaptureAdapter)?.Id;
        adapters.Items.Clear();
        try
        {
            foreach (CaptureAdapter adapter in NpcapCapture.ListAdapters())
            {
                adapters.Items.Add(adapter);
            }
            if (adapters.Items.Count == 0)
            {
                status.Text = "未找到可用的抓包接口。";
                return;
            }
            int previousIndex = adapters.Items.Cast<CaptureAdapter>().ToList().FindIndex(a => a.Id == previous);
            adapters.SelectedIndex = previousIndex >= 0 ? previousIndex : 0;
            status.Text = "选择接口后开始抓包。";
        }
        catch (Exception error)
        {
            status.Text = error.Message;
        }
    }

    private void BeginCapture()
    {
        if (captureTask is not null || adapters.SelectedItem is not CaptureAdapter adapter)
        {
            return;
        }

        ClearHistory();
        received = 0;
        skipped = 0;
        captureError = null;
        ownerError = null;
        opened = false;
        cancellation = new CancellationTokenSource();
        var token = cancellation.Token;
        start.Enabled = false;
        stop.Enabled = true;
        adapters.Enabled = false;
        refresh.Enabled = false;
        status.Text = "正在打开抓包接口…";
        string? captureFilter = demoCaptureFilter;
        captureTask = Task.Run(() => RunCapture(adapter, captureFilter, token));
    }

    private void RunCapture(CaptureAdapter adapter, string? captureFilter, CancellationToken token)
    {
        try
        {
            using var source = new NpcapCapture(adapter, captureFilter);
            var lookup = new TcpProcessLookup();
            opened = true;
            while (!token.IsCancellationRequested)
            {
                if (!source.TryRead(out var bytes, out var timestamp, out int length))
                {
                    if (token.WaitHandle.WaitOne(15))
                    {
                        break;
                    }
                    continue;
                }
                Interlocked.Increment(ref received);
                if (Volatile.Read(ref pendingCount) >= PendingLimit)
                {
                    Interlocked.Increment(ref skipped);
                    continue;
                }
                PacketInfo packet = PacketDecoder.Decode(bytes, source.LinkType, timestamp, length);
                var owners = lookup.Find(TcpFlowKey.From(packet));
                Volatile.Write(ref ownerError, lookup.Error);
                Interlocked.Increment(ref pendingCount);
                pending.Enqueue((packet, owners));
            }
        }
        catch (Exception error)
        {
            captureError = error.Message;
        }
    }

    private void RequestStop()
    {
        cancellation?.Cancel();
        stop.Enabled = false;
        status.Text = "正在停止抓包…";
    }

    private void OnTick()
    {
        SynchronizeRows();
        if (captureTask is { IsCompleted: true })
        {
            captureTask = null;
            cancellation?.Dispose();
            cancellation = null;
            adapters.Enabled = true;
            refresh.Enabled = true;
            start.Enabled = adapters.SelectedItem is CaptureAdapter;
            stop.Enabled = false;
            status.Text = captureError ?? "抓包已停止。";
            if (closing)
            {
                Close();
            }
        }
        else if (captureTask is not null && opened && stop.Enabled)
        {
            status.Text = Volatile.Read(ref ownerError) is string warning
                ? $"正在抓包 · {warning}" : "正在抓包";
        }
    }

    private void SynchronizeRows()
    {
        bool changed = false;
        for (int i = 0; i < 400 && pending.TryDequeue(out var item); i++)
        {
            Interlocked.Decrement(ref pendingCount);
            var row = new ObservedPacket(++nextNumber, item.Packet, TcpFlowKey.From(item.Packet), item.Owners);
            history.Add(row);
            foreach (var process in item.Owners)
            {
                if (knownOwners.TryAdd(process.Id, process))
                {
                    owner.Items.Add(new OwnerChoice(process.ToString(), process.Id));
                }
            }
            changed = true;
        }
        if (changed)
        {
            int surplus = history.Count - HistoryLimit;
            if (surplus > 0)
            {
                history.RemoveRange(0, surplus);
            }
            Rebuild();
        }
        UpdateCounts();
    }

    private void ClearHistory()
    {
        while (pending.TryDequeue(out _))
        {
            Interlocked.Decrement(ref pendingCount);
        }
        history.Clear();
        knownOwners.Clear();
        nextNumber = 0;
        flow = null;
        owner.Items.Clear();
        owner.Items.Add(new OwnerChoice("所有进程", null));
        owner.SelectedIndex = 0;
        Rebuild();
    }

    private ObservedPacket? SelectedRow()
    {
        int index = grid.CurrentCell?.RowIndex ?? -1;
        return index >= 0 && index < visible.Count ? visible[index] : null;
    }

    private void SelectFlow()
    {
        if (SelectedRow()?.Flow is TcpFlowKey key)
        {
            flow = key;
            protocol.SelectedIndex = 0;
            owner.SelectedIndex = 0;
            Rebuild();
        }
    }

    private void Rebuild()
    {
        long? selectedNumber = SelectedRow()?.Number;
        var activeProtocol = (protocol.SelectedItem as ProtocolChoice)?.Value ?? ProtocolFilter.All;
        int? activeOwner = (owner.SelectedItem as OwnerChoice)?.Id;
        visible.Clear();
        int selectedIndex = -1;
        foreach (var row in history)
        {
            if (!PacketFilters.Matches(row.Packet, activeProtocol) ||
                (flow is not null && row.Flow != flow) ||
                (activeOwner is int id && !row.Owners.Any(p => p.Id == id)))
            {
                continue;
            }
            if (row.Number == selectedNumber)
            {
                selectedIndex = visible.Count;
            }
            visible.Add(row);
        }
        grid.RowCount = visible.Count;
        if (visible.Count > 0)
        {
            int index = selectedIndex >= 0 ? selectedIndex : 0;
            if (grid.CurrentCell?.RowIndex != index)
            {
                grid.CurrentCell = grid[0, index];
            }
        }
        selection.Text = flow is TcpFlowKey key ? $"TCP 流  {key}" : "按协议或本机进程筛选，选中 TCP 包可追踪双向报文。";
        grid.Invalidate();
        ShowDetails();
        UpdateCounts();
    }

    private void ShowDetails()
    {
        var row = SelectedRow();
        followFlow.Enabled = row?.Flow is not null;
        string text = row is ObservedPacket selected
            ? $"#{selected.Number}  {ProtocolName(selected.Packet)}  |  {selected.Packet.WireLength} 字节\r\n" +
              $"{FormatEndpoint(selected.Packet.Source, selected.Packet.SourcePort)} → " +
              $"{FormatEndpoint(selected.Packet.Destination, selected.Packet.DestinationPort)}\r\n" +
              (selected.Flow is not null
                  ? $"本机进程：{(selected.Owners.Length == 0 ? "未匹配" : string.Join("、", selected.Owners.Select(p => p.ToString())))}\r\n"
                  : "") + selected.Packet.Details
            : "选择一条数据包查看协议字段。";
        if (detail.Text != text)
        {
            detail.Text = text;
        }
    }

    private void UpdateCounts()
    {
        counts.Text = $"接收 {Interlocked.Read(ref received)}  ·  保留 {history.Count}  ·  显示 {visible.Count}" +
            (Volatile.Read(ref skipped) > 0 ? $"  ·  队列丢弃 {Volatile.Read(ref skipped)}" : "");
    }

    internal async Task RunDemoAsync(string logPath)
    {
        var log = new List<string>();
        try
        {
            await Task.Delay(2_000);
            Require(adapters.SelectedItem is CaptureAdapter adapter &&
                adapter.Id.Equals(@"\Device\NPF_Loopback", StringComparison.OrdinalIgnoreCase), "默认选中本机回环接口");
            string trafficInfoPath = logPath + ".traffic.json";
            await WaitUntilAsync(() => File.Exists(trafficInfoPath));
            using var trafficInfo = JsonDocument.Parse(File.ReadAllText(trafficInfoPath));
            var ports = trafficInfo.RootElement;
            int tcpClient = ports.GetProperty("TcpClientPort").GetUInt16();
            int tcpServer = ports.GetProperty("TcpServerPort").GetUInt16();
            int udpSource = ports.GetProperty("UdpSourcePort").GetUInt16();
            int udpTarget = ports.GetProperty("UdpTargetPort").GetUInt16();
            // NSCP is the prefix of the echo payload emitted by Start-DemoTraffic.ps1.
            demoCaptureFilter = $"(src host 127.0.0.1 and dst host 127.0.0.1 and " +
                $"((tcp and port {tcpClient} and port {tcpServer}) or " +
                $"(udp and src port {udpSource} and dst port {udpTarget}) or " +
                "(icmp and icmp[8:4] = 0x4e534350))) or " +
                "(src host ::1 and dst host ::1 and icmp6 and ip6[48:4] = 0x4e534350)";
            start.PerformClick();
            await WaitUntilAsync(() => opened && history.Count > 0);
            Require(stop.Enabled, "界面开始抓包并更新列表");
            await Task.Delay(3_000);
            foreach (var filter in new[] { ProtocolFilter.Http, ProtocolFilter.Udp, ProtocolFilter.IPv6, ProtocolFilter.Icmp })
            {
                protocol.SelectedItem = protocol.Items.Cast<ProtocolChoice>().First(item => item.Value == filter);
                await WaitUntilAsync(() => visible.Count > 0);
                Require(visible.All(item => PacketFilters.Matches(item.Packet, filter)), $"界面筛选 {filter}");
                await Task.Delay(2_300);
            }

            reset.PerformClick();
            int rowIndex = visible.FindIndex(item => item.Packet.IsHttp && item.Flow is not null && item.Owners.Length > 0);
            Require(rowIndex >= 0, "选中带进程归属的 HTTP 报文");
            grid.CurrentCell = grid[0, rowIndex];
            ProcessOwner match = visible[rowIndex].Owners[0];
            await Task.Delay(1_500);
            followFlow.PerformClick();
            Require(flow is not null && visible.Count >= 2 && visible.All(item => item.Flow == flow), "界面追踪双向 TCP 流");
            await Task.Delay(3_000);
            reset.PerformClick();
            owner.SelectedItem = owner.Items.Cast<OwnerChoice>().First(item => item.Id == match.Id);
            Require(visible.Count > 0 && visible.All(item => item.Owners.Any(process => process.Id == match.Id)), "界面按本机 PID 筛选");
            await Task.Delay(3_000);
            stop.PerformClick();
            await WaitUntilAsync(() => start.Enabled);
            Require(status.Text == "抓包已停止。", "界面停止抓包");
            await Task.Delay(1_700);
            start.PerformClick();
            await WaitUntilAsync(() => opened && history.Count > 0);
            Require(stop.Enabled, "界面重启并接收新报文");
            stop.PerformClick();
            await WaitUntilAsync(() => start.Enabled);
            await Task.Delay(3_500);
        }
        catch (Exception error)
        {
            DemoExitCode = 1;
            log.Add($"FAIL {error.Message}");
        }
        finally
        {
            File.WriteAllLines(logPath, log);
            Close();
        }

        void Require(bool condition, string check)
        {
            if (!condition)
            {
                throw new InvalidOperationException(check);
            }
            log.Add($"PASS {check}");
        }

        static async Task WaitUntilAsync(Func<bool> condition)
        {
            long stopAt = Environment.TickCount64 + 5_000;
            while (!condition())
            {
                if (Environment.TickCount64 >= stopAt)
                {
                    throw new TimeoutException("等待界面状态更新超时。请运行本机演示流量脚本。");
                }
                await Task.Delay(75);
            }
        }
    }
}
