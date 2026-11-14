# NetScope 构建与部署

本项目以 Windows x64 为发布目标，使用 C#、.NET 10 Windows Forms 和 Npcap。

## 构建与发布

1. 开发机安装 [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) 和 [Npcap 驱动](https://npcap.com/#download)，运行 `dotnet --list-sdks` 确认已安装 10.0 SDK。项目通过 P/Invoke 调用 Npcap，编译源码只需 .NET SDK，实抓时才需要 Npcap。
2. 在 PowerShell 中进入源码目录，也就是包含 `ExperimentA.csproj` 的目录。执行以下命令。

   ```powershell
   dotnet run --project .\tests\ExperimentA.Checks.csproj -c Release
   dotnet publish .\ExperimentA.csproj -c Release -r win-x64 --self-contained true
   ```

3. 发布目录为 `bin\Release\net10.0-windows\win-x64\publish\`。把整个目录复制到目标 Windows x64 机器，单独安装 Npcap，再双击目录中的 `NetScope.exe`。发布产物已包含 .NET 运行时。安装 Npcap 时若启用了仅管理员访问，打开抓包接口需要授权。

## 本机验收与演示

可以先运行回环自检。把以下命令中的路径指向实际发布目录。自检使用本机生成的流量，结果写入临时目录。

```powershell
$exe = (Resolve-Path .\bin\Release\net10.0-windows\win-x64\publish\NetScope.exe).Path
$result = Join-Path $env:TEMP 'netscope-loopback.txt'
Start-Process -FilePath $exe -ArgumentList @('--verify-loopback', ('"{0}"' -f $result)) -WindowStyle Hidden -Wait
Get-Content -LiteralPath $result -Encoding UTF8
```

1. 启动 `NetScope.exe`，选择「本机回环接口（Npcap）」，点击「开始抓包」。
2. 在源码目录另开 PowerShell，运行以下命令。脚本将在本机产生明文 HTTP/1.1、UDP 和回环 ICMP 流量，并输出 PowerShell 的 PID。脚本保留 HTTP TCP 连接，便于验证进程匹配。

   ```powershell
   .\tools\Start-DemoTraffic.ps1 -DurationSeconds 45
   ```

3. 在程序中分别切换 HTTP、TCP、UDP、IPv4、IPv6 和 ICMP 筛选，选中数据包检查地址、端口及协议头部详情。ICMP 筛选包含 ICMPv6，IPv6 结果取决于机器是否启用了 IPv6 回环。
4. 选中一条 HTTP/TCP 报文，点击「追踪 TCP 流」，确认同一连接的双向报文。重置筛选后，在「本机进程」中选择脚本输出的 PID，查看匹配的 TCP 流量。进程归属来自周期查询的系统 TCP 连接表，短连接可能在查询前关闭。
5. 停止抓包并再次开始，确认界面仍可接收新包。HTTP 按单个 TCP 段内完整的明文 HTTP/1.x 起始行识别，跨段起始行和 HTTPS 流量没有 HTTP 标签。

如需自动核对发布版的实抓结果，在包含 `NetScope.exe` 的发布目录运行以下命令。检查只匹配程序自行生成的本机回环流量，结果写到指定的文本文件。

```powershell
$log = Join-Path (Get-Location) 'loopback-check.txt'
$process = Start-Process .\NetScope.exe -ArgumentList @('--verify-loopback', ('"' + $log + '"')) -Wait -PassThru
Get-Content -Encoding UTF8 -LiteralPath $log
$process.ExitCode
```
