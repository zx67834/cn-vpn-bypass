# StrongVPN 国内直连。给常用国内网段加一条比 VPN 更具体的路由，流量走当前局域网网关。
# 双击「直连国内.bat」。换 Wi-Fi / 网线，或重启之后，再双击一次。
param(
    [switch]$Undo,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { chcp 65001 > $null } catch { }
$Root = $PSScriptRoot
$LogPath = Join-Path $Root 'last-run.log'
$StatePath = Join-Path $Root 'state.txt'
$CidrPath = Join-Path $Root 'cn-cidrs.txt'
$ExtraPath = Join-Path $Root 'extra-ips.txt'
$utf8 = New-Object System.Text.UTF8Encoding $true
$script:LogWriter = New-Object System.IO.StreamWriter($LogPath, $false, $utf8)

function Write-Log([string]$Message) {
    $line = '{0}  {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message
    $script:LogWriter.WriteLine($line)
    $script:LogWriter.Flush()
    Write-Host $line
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-VpnPeers {
    $peers = New-Object System.Collections.Generic.List[string]
    $procs = @(Get-Process -Name 'openvpn' -ErrorAction SilentlyContinue)
    foreach ($proc in $procs) {
        $conns = @(Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue)
        foreach ($conn in $conns) {
            $remote = [string]$conn.RemoteAddress
            if ($remote -and $remote -ne '0.0.0.0' -and $remote -notmatch ':') {
                if (-not $peers.Contains($remote)) { $peers.Add($remote) }
            }
        }
    }
    return @($peers)
}

function Get-LanGateway {
    $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -and [string]$_.NextHop -ne '0.0.0.0' })
    $cands = @()
    foreach ($route in $routes) {
        $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
        if (-not $adapter -or [string]$adapter.Status -ne 'Up') { continue }
        $desc = [string]$adapter.InterfaceDescription
        $name = [string]$adapter.Name
        if ($desc -match 'TAP-Windows|ZeroTier|VirtualBox|VMware|Hyper-V|Bluetooth|Wintun|WireGuard|Loopback') { continue }
        if ($name -match 'ZeroTier|VMware|VirtualBox') { continue }
        $hop = [string]$route.NextHop
        if ([BypassVpn.Routes]::IsCgnat($hop) -or $hop -eq '25.255.255.254') { continue }
        $ifMetric = 0
        $ipif = Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($ipif) { $ifMetric = [int]$ipif.InterfaceMetric }
        $cands += [pscustomobject]@{
            NextHop     = $hop
            IfIndex     = [int]$route.InterfaceIndex
            Name        = $name
            Description = $desc
            Total       = ([int]$route.RouteMetric) + $ifMetric
        }
    }
    return @($cands | Sort-Object Total, IfIndex | Select-Object -First 1)
}

function Get-RouteMap {
    $map = @{}
    Get-NetRoute -AddressFamily IPv4 | ForEach-Object {
        $key = [string]$_.DestinationPrefix
        if (-not $map.ContainsKey($key)) {
            $map[$key] = New-Object 'System.Collections.Generic.List[object]'
        }
        $map[$key].Add($_) | Out-Null
    }
    return $map
}

function Test-RoutePresent([string]$Cidr, [string]$Gateway, [int]$IfIndex) {
    $row = @(Get-NetRoute -DestinationPrefix $Cidr -ErrorAction SilentlyContinue |
        Where-Object { [string]$_.NextHop -eq $Gateway -and [int]$_.InterfaceIndex -eq $IfIndex })
    return ($row.Count -gt 0)
}

if (-not ('BypassVpn.Routes' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace BypassVpn {
    public static class Routes {
        [StructLayout(LayoutKind.Sequential)]
        public struct Row {
            public uint dwForwardDest;
            public uint dwForwardMask;
            public uint dwForwardPolicy;
            public uint dwForwardNextHop;
            public uint dwForwardIfIndex;
            public uint dwForwardType;
            public uint dwForwardProto;
            public uint dwForwardAge;
            public uint dwForwardNextHopAS;
            public uint dwForwardMetric1;
            public uint dwForwardMetric2;
            public uint dwForwardMetric3;
            public uint dwForwardMetric4;
            public uint dwForwardMetric5;
        }

        [DllImport("iphlpapi.dll")]
        public static extern int CreateIpForwardEntry(ref Row row);

        [DllImport("iphlpapi.dll")]
        public static extern int DeleteIpForwardEntry(ref Row row);

        public static bool IsCgnat(string ip) {
            IPAddress parsed;
            if (!IPAddress.TryParse(ip, out parsed)) return false;
            byte[] b = parsed.GetAddressBytes();
            return b.Length == 4 && b[0] == 100 && b[1] >= 64 && b[1] <= 127;
        }

        static uint Host(string ip) {
            byte[] b = IPAddress.Parse(ip).GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        static uint MaskOf(int prefix) {
            if (prefix <= 0) return 0;
            if (prefix >= 32) return 0xFFFFFFFFu;
            return 0xFFFFFFFFu << (32 - prefix);
        }

        static string Format(uint value) {
            return string.Format("{0}.{1}.{2}.{3}",
                (value >> 24) & 255, (value >> 16) & 255, (value >> 8) & 255, value & 255);
        }

        public static uint Pack(string ip, int mode) {
            byte[] b = IPAddress.Parse(ip).GetAddressBytes();
            if (mode == 0) {
                return (uint)b[0] | ((uint)b[1] << 8) | ((uint)b[2] << 16) | ((uint)b[3] << 24);
            }
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        static bool IsBogon(uint network, int prefix) {
            uint[] nets = new uint[] {
                Host("0.0.0.0"), Host("10.0.0.0"), Host("127.0.0.0"), Host("169.254.0.0"),
                Host("172.16.0.0"), Host("192.168.0.0"), Host("100.64.0.0"), Host("224.0.0.0")
            };
            int[] lens = new int[] { 8, 8, 8, 16, 12, 16, 10, 3 };
            uint start = network;
            uint end = network | ~MaskOf(prefix);
            for (int i = 0; i < nets.Length; i++) {
                uint bStart = nets[i];
                uint bEnd = nets[i] | ~MaskOf(lens[i]);
                if (start <= bEnd && bStart <= end) return true;
            }
            return false;
        }

        public static string Normalize(string line) {
            if (line == null) return "";
            string text = line.Trim().TrimStart('\uFEFF');
            if (text.Length == 0 || text.StartsWith("#")) return "";
            string[] parts = text.Split('/');
            if (parts.Length > 2) return "";
            IPAddress ip;
            if (!IPAddress.TryParse(parts[0].Trim(), out ip)) return "";
            int prefix = 32;
            if (parts.Length == 2 && !int.TryParse(parts[1].Trim(), out prefix)) return "";
            if (prefix < 1 || prefix > 32) return "";
            byte[] raw = ip.GetAddressBytes();
            if (raw.Length != 4) return "";
            uint value = Host(parts[0].Trim());
            value &= MaskOf(prefix);
            if (IsBogon(value, prefix)) return "";
            return Format(value) + "/" + prefix.ToString();
        }

        public static bool ContainsIp(string cidr, string ip) {
            int slash = cidr.IndexOf('/');
            if (slash < 0) return false;
            int prefix;
            if (!int.TryParse(cidr.Substring(slash + 1), out prefix)) return false;
            uint network = Host(cidr.Substring(0, slash));
            uint addr;
            try { addr = Host(ip); } catch { return false; }
            return (addr & MaskOf(prefix)) == (network & MaskOf(prefix));
        }

        public static string[] Filter(string[] lines) {
            var seen = new Dictionary<string, bool>();
            var result = new List<string>();
            if (lines == null) return result.ToArray();
            foreach (string line in lines) {
                string cidr = Normalize(line);
                if (cidr.Length == 0 || seen.ContainsKey(cidr)) continue;
                seen[cidr] = true;
                result.Add(cidr);
            }
            return result.ToArray();
        }

        static Row Build(string cidr, string gateway, int ifIndex, int mode, bool unusedMetric, int metric) {
            int slash = cidr.IndexOf('/');
            string dest = cidr.Substring(0, slash);
            int prefix = int.Parse(cidr.Substring(slash + 1));
            uint maskHost = MaskOf(prefix);
            string maskIp = Format(maskHost);
            Row row = new Row();
            row.dwForwardDest = Pack(dest, mode);
            row.dwForwardMask = Pack(maskIp, mode);
            row.dwForwardNextHop = Pack(gateway, mode);
            row.dwForwardIfIndex = (uint)ifIndex;
            row.dwForwardType = 4;
            row.dwForwardProto = 3;
            row.dwForwardMetric1 = metric < 1 ? 1u : (uint)metric;
            uint unused = unusedMetric ? 0xFFFFFFFFu : 0u;
            row.dwForwardMetric2 = unused;
            row.dwForwardMetric3 = unused;
            row.dwForwardMetric4 = unused;
            row.dwForwardMetric5 = unused;
            return row;
        }

        public static int Add(string cidr, string gateway, int ifIndex, int mode, bool unusedMetric, int metric) {
            Row row = Build(cidr, gateway, ifIndex, mode, unusedMetric, metric);
            return CreateIpForwardEntry(ref row);
        }

        public static int Delete(string cidr, string gateway, int ifIndex, int mode, bool unusedMetric, int metric) {
            Row row = Build(cidr, gateway, ifIndex, mode, unusedMetric, metric);
            return DeleteIpForwardEntry(ref row);
        }
    }
}
'@
}

function Get-DesiredCidrs {
    $raw = New-Object System.Collections.Generic.List[string]
    foreach ($path in @($CidrPath, $ExtraPath)) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        foreach ($line in [System.IO.File]::ReadAllLines($path)) { $raw.Add($line) }
    }
    foreach ($anchor in @(
        '114.114.114.114/32',
        '114.114.115.115/32',
        '223.5.5.5/32',
        '223.6.6.6/32',
        '180.76.76.76/32',
        '119.29.29.29/32'
    )) { $raw.Add($anchor) }
    return @([BypassVpn.Routes]::Filter($raw.ToArray()))
}

function Select-SafeCidrs([string[]]$Cidrs, [string[]]$Protect) {
    $keep = New-Object System.Collections.Generic.List[string]
    $dropped = New-Object System.Collections.Generic.List[string]
    foreach ($cidr in $Cidrs) {
        $hit = ''
        foreach ($ip in $Protect) {
            if ([BypassVpn.Routes]::ContainsIp($cidr, $ip)) { $hit = $ip; break }
        }
        if ($hit) { $dropped.Add("$cidr 含有 $hit，已跳过") | Out-Null }
        else { $keep.Add($cidr) | Out-Null }
    }
    return [pscustomobject]@{ Keep = @($keep); Dropped = @($dropped) }
}

function Find-PackMode([string]$Gateway, [int]$IfIndex) {
    $ifMetric = 1
    $ipif = Get-NetIPInterface -InterfaceIndex $IfIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($ipif -and [int]$ipif.InterfaceMetric -gt 0) { $ifMetric = [int]$ipif.InterfaceMetric }
    $tries = @(
        @{ Mode = 0; Unused = $true; Metric = $ifMetric },
        @{ Mode = 0; Unused = $false; Metric = $ifMetric },
        @{ Mode = 0; Unused = $true; Metric = 256 },
        @{ Mode = 1; Unused = $true; Metric = $ifMetric }
    )
    foreach ($try in $tries) {
        $rc = [BypassVpn.Routes]::Add('203.0.113.0/24', $Gateway, $IfIndex, [int]$try.Mode, [bool]$try.Unused, [int]$try.Metric)
        Start-Sleep -Milliseconds 200
        $ok = Test-RoutePresent '203.0.113.0/24' $Gateway $IfIndex
        [void][BypassVpn.Routes]::Delete('203.0.113.0/24', $Gateway, $IfIndex, [int]$try.Mode, [bool]$try.Unused, [int]$try.Metric)
        if ($ok) { return $try }
        Write-Log ("路由写入试探未生效 mode={0} unused={1} metric={2} 返回值={3}" -f $try.Mode, $try.Unused, $try.Metric, $rc)
    }
    return $null
}

function Remove-ManagedRoute($Route, $Pack) {
    $hop = [string]$Route.NextHop
    if (-not $hop -or $hop -eq '0.0.0.0') { return $false }
    if ([string]$Route.Protocol -ne 'NetMgmt') { return $false }
    $rc = [BypassVpn.Routes]::Delete([string]$Route.DestinationPrefix, $hop, [int]$Route.InterfaceIndex, [int]$Pack.Mode, [bool]$Pack.Unused, [int]$Pack.Metric)
    return ($rc -eq 0 -or $rc -eq 1168)
}

function Save-State([string]$Gateway, [int]$IfIndex, [string]$Name, [string[]]$Cidrs) {
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('gateway=' + $Gateway)
    $lines.Add('ifIndex=' + $IfIndex)
    $lines.Add('ifName=' + $Name)
    $lines.Add('time=' + (Get-Date).ToString('s'))
    foreach ($cidr in $Cidrs) { $lines.Add($cidr) }
    [System.IO.File]::WriteAllLines($StatePath, $lines.ToArray(), $utf8)
}

function Read-StateCidrs {
    if (-not (Test-Path -LiteralPath $StatePath)) { return @() }
    $cidrs = New-Object System.Collections.Generic.List[string]
    foreach ($line in [System.IO.File]::ReadAllLines($StatePath)) {
        $text = $line.Trim()
        if ($text -match '^\d+\.\d+\.\d+\.\d+/\d+$') { $cidrs.Add($text) }
    }
    return @($cidrs)
}

function Get-ExtraHosts {
    $hosts = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $ExtraPath)) { return @() }
    foreach ($line in [System.IO.File]::ReadAllLines($ExtraPath)) {
        $text = $line.Trim().TrimStart([char]0xFEFF)
        if ($text.Length -eq 0 -or $text.StartsWith('#')) { continue }
        $ip = $text.Split('/')[0].Trim()
        if ($ip -match '^\d+\.\d+\.\d+\.\d+$' -and -not $hosts.Contains($ip)) { $hosts.Add($ip) }
    }
    return @($hosts)
}

try {
    $admin = Test-Admin
    if (-not $admin -and -not $DryRun) {
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
        if ($Undo) { $argList += '-Undo' }
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
        Write-Log '当前不是管理员，已请求提升权限。'
        return
    }

    Write-Log $(if ($Undo) { '开始取消国内直连' } elseif ($DryRun) { '预览，不改路由' } else { '开始添加国内直连' })
    $lan = Get-LanGateway
    if (-not $lan) {
        Write-Log '没有找到可用的局域网网关。请先连上 Wi-Fi 或网线。'
        exit 1
    }
    $gw = [string]$lan.NextHop
    $ifIndex = [int]$lan.IfIndex
    $ifName = [string]$lan.Name
    Write-Log ("局域网网关 {0}，网卡 {1}，接口 {2}" -f $gw, $ifName, $ifIndex)

    $peers = @(Get-VpnPeers)
    if ($peers.Count -gt 0) {
        Write-Log ("VPN 服务器 {0}，这段地址继续走隧道" -f ($peers -join ', '))
    } else {
        Write-Log '没有检测到 OpenVPN 连接。国内网段仍会改走局域网。'
    }

    $protect = New-Object System.Collections.Generic.List[string]
    foreach ($peer in $peers) { $protect.Add($peer) }
    foreach ($ip in @('1.1.1.1', '8.8.8.8', '100.64.8.1')) { $protect.Add($ip) }

    $desired = @(Get-DesiredCidrs)
    $safe = Select-SafeCidrs $desired @($protect)
    $cidrs = @($safe.Keep)
    foreach ($drop in @($safe.Dropped)) { Write-Log $drop }
    Write-Log ("国内网段 {0} 条" -f $cidrs.Count)
    if ($cidrs.Count -eq 0) {
        Write-Log '没有可添加的网段。'
        exit 1
    }

    $extraHosts = @(Get-ExtraHosts)
    $directSamples = New-Object System.Collections.Generic.List[string]
    foreach ($sample in $extraHosts) { $directSamples.Add($sample) }
    foreach ($sample in @('114.114.114.114', '223.5.5.5', '180.76.76.76', '119.29.29.29')) {
        if (-not $directSamples.Contains($sample)) { $directSamples.Add($sample) }
    }
    foreach ($sample in $directSamples) {
        $covered = $false
        foreach ($cidr in $cidrs) {
            if ([BypassVpn.Routes]::ContainsIp($cidr, $sample)) { $covered = $true; break }
        }
        if (-not $covered) { Write-Log ("警告：{0} 不在直连名单里" -f $sample) }
    }

    if ($DryRun) {
        Write-Log '预览结束。双击「直连国内.bat」才会写入路由。'
        exit 0
    }

    $pack = Find-PackMode $gw $ifIndex
    if (-not $pack) {
        Write-Log '无法写入路由。请确认这个窗口是用管理员打开的。'
        exit 1
    }

    $old = @(Read-StateCidrs)
    $map = Get-RouteMap
    $removed = 0
    $added = 0
    $kept = 0
    $failed = 0
    $failSamples = New-Object System.Collections.Generic.List[string]

    if ($Undo) {
        $todo = @($cidrs)
        if ($old.Count -gt 0) { $todo = @($old) }
        $i = 0
        foreach ($cidr in $todo) {
            $i++
            if ($map.ContainsKey($cidr)) {
                foreach ($route in $map[$cidr]) {
                    if (Remove-ManagedRoute $route $pack) { $removed++ }
                }
            }
            if (($i % 1000) -eq 0) { Write-Log ("已处理 {0} / {1}" -f $i, $todo.Count) }
        }
        if (Test-Path -LiteralPath $StatePath) { Remove-Item -LiteralPath $StatePath -Force }
        Write-Log ("已删除 {0} 条直连路由" -f $removed)
    } else {
        $want = @{}
        foreach ($cidr in $cidrs) { $want[$cidr] = $true }
        foreach ($cidr in $old) {
            if ($want.ContainsKey($cidr)) { continue }
            if ($map.ContainsKey($cidr)) {
                foreach ($route in $map[$cidr]) {
                    if (Remove-ManagedRoute $route $pack) { $removed++ }
                }
            }
        }
        $i = 0
        foreach ($cidr in $cidrs) {
            $i++
            try {
                $have = $false
                if ($map.ContainsKey($cidr)) {
                    foreach ($route in $map[$cidr]) {
                        $hop = [string]$route.NextHop
                        $routeIf = $route.InterfaceIndex -as [int]
                        if ($null -eq $routeIf) { $routeIf = -1 }
                        if ($hop -eq $gw -and $routeIf -eq $ifIndex) { $have = $true; continue }
                        if (Remove-ManagedRoute $route $pack) { $removed++ }
                    }
                }
                if ($have) { $kept++; continue }
                $rc = [BypassVpn.Routes]::Add($cidr, $gw, $ifIndex, [int]$pack.Mode, [bool]$pack.Unused, [int]$pack.Metric)
                if ($rc -eq 0 -or $rc -eq 5010) { $added++ }
                else {
                    $failed++
                    if ($failSamples.Count -lt 8) { [void]$failSamples.Add("$cidr 返回值=$rc") }
                }
            } catch {
                $failed++
                if ($failSamples.Count -lt 8) { [void]$failSamples.Add("$cidr $($_.Exception.Message)") }
            }
            if (($i % 1000) -eq 0) { Write-Log ("已处理 {0} / {1}" -f $i, $cidrs.Count) }
        }
        Save-State $gw $ifIndex $ifName $cidrs
        Write-Log ("新增 {0}，已存在 {1}，替换旧路由 {2}，失败 {3}" -f $added, $kept, $removed, $failed)
        foreach ($sample in @($failSamples)) { Write-Log $sample }
    }

    Write-Log '当前选路：'
    $checkIps = New-Object System.Collections.Generic.List[string]
    foreach ($sample in $extraHosts) { $checkIps.Add($sample) }
    foreach ($sample in @('114.114.114.114', '223.5.5.5', '1.1.1.1', '8.8.8.8')) {
        if (-not $checkIps.Contains($sample)) { $checkIps.Add($sample) }
    }
    foreach ($peer in $peers) {
        if (-not $checkIps.Contains($peer)) { $checkIps.Add($peer) }
    }
    foreach ($ip in $checkIps) {
        $picked = @(Find-NetRoute -RemoteIPAddress $ip -ErrorAction SilentlyContinue |
            Where-Object { $_.DestinationPrefix }) | Select-Object -First 1
        if (-not $picked) {
            Write-Log ("{0}  没有匹配路由" -f $ip)
            continue
        }
        $hop = [string]$picked.NextHop
        $alias = [string]$picked.InterfaceAlias
        $prefix = [string]$picked.DestinationPrefix
        $viaVpn = ($hop -eq '100.64.8.1' -or $alias -match 'TAP|以太网 3')
        $kind = $(if ($viaVpn) { '走 VPN' } else { '直连' })
        Write-Log ("{0}  {1}  {2}  下一跳 {3}  {4}" -f $ip, $kind, $prefix, $hop, $alias)
    }

    if (-not $Undo -and $extraHosts.Count -gt 0) {
        $probe = [string]$extraHosts[0]
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $wait = $client.BeginConnect($probe, 443, $null, $null)
            $opened = $wait.AsyncWaitHandle.WaitOne(4000, $false)
            if ($opened -and $client.Connected) { Write-Log ("{0}:443 可以连上" -f $probe) }
            else { Write-Log ("{0}:443 4 秒内没连上" -f $probe) }
        } catch {
            Write-Log ("{0}:443 连接失败" -f $probe)
        } finally {
            $client.Dispose()
        }
    }
} catch {
    Write-Log ("出错：{0}" -f $_.Exception.Message)
    if ($_.ScriptStackTrace) { Write-Log $_.ScriptStackTrace }
    exit 1
} finally {
    if ($script:LogWriter) { $script:LogWriter.Dispose() }
}
