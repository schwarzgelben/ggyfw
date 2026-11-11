#requires -Version 5.1
# po0fw - GGY (咕咕云) 防火墙自动加白与流量查询 (Windows)
# 用法: powershell -File po0fw.ps1 -Tokens "token1,token2" [-Slot "0"]
param(
    [string]$Tokens = $env:PO0FW_TOKENS,
    [string]$Slot = $env:PO0FW_SLOT,
    [string]$ApiBase = "https://www.guguyun.com/cany_tencentecs/firewall/whitelist",
    [string]$TrafficApiBase = "https://www.guguyun.com/cany_tencentecs/traffic/query",
    [string]$UaMode = "mobile",
    [switch]$Status,
    [switch]$Traffic
)

$confPath = Join-Path $env:ProgramData "po0fw\po0fw.conf"
if (-not $Tokens -and (Test-Path $confPath)) {
    $Tokens = (Get-Content $confPath -Raw).Trim()
}
if (-not $Tokens) {
    Write-Error "未配置 token。用 -Tokens 参数或写入 $confPath"
    exit 1
}

# 强制 TLS1.2+
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor 3072

$userAgent = if ($UaMode -eq "pc") {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
} else {
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
}

function Get-GgyToken {
    param([string]$InputStr)
    $s = $InputStr.Trim()
    if ($s -match '[?&]token=([^&#\s]+)') {
        return [System.Uri]::UnescapeDataString($matches[1])
    }
    if ($s -match '^https?://') {
        return ""
    }
    return $s
}

$fail = $false
$idx = 0
foreach ($entry in $Tokens.Split(',')) {
    $idx++
    $entry = $entry.Trim()
    if (-not $entry) { continue }
    $tok = Get-GgyToken -InputStr $entry
    if (-not $tok) { continue }

    # 槽位处理
    if ($tok -notmatch '@' -and $Slot) {
        $tok = "$tok@$Slot"
    }

    $baseTok = $tok -replace '@.*$', ''
    $short = $baseTok.Substring(0, [Math]::Min(12, $baseTok.Length))
    $slotHint = if ($tok -match '@(.*)$') { " @$($matches[1])" } else { "" }
    
    if (-not $Traffic) {
        $url = "$ApiBase`?token=$tok"
        try {
            $res = Invoke-RestMethod -Method Get -Uri $url -TimeoutSec 20 -Headers @{ "Accept" = "application/json"; "User-Agent" = $userAgent }
            $resStatus = $res.status
            $msg = $res.msg
            if ($resStatus -eq 200) {
                Write-Host "[po0fw] #$idx [$short…$slotHint] ✅ 加白成功: $msg"
            } else {
                Write-Host "[po0fw] #$idx [$short…] ❌ 加白失败 (status=$resStatus): $msg"
                $fail = $true
            }
        } catch {
            Write-Host "[po0fw] #$idx [$short…] ❌ 请求异常: $_"
            $fail = $true
        }
    }

    # 查询流量信息（使用纯净 baseTok）
    $tUrl = "$TrafficApiBase`?token=$baseTok"
    try {
        $tRes = Invoke-RestMethod -Method Get -Uri $tUrl -TimeoutSec 10 -Headers @{ "Accept" = "application/json"; "User-Agent" = $userAgent }
        if ($tRes.status -eq 200 -and $tRes.data) {
            $d = $tRes.data
            $u = if ($d.used) { $d.used } else { $d.traffic_used }
            $tot = if ($d.total) { $d.total } else { $d.traffic_total }
            $rst = if ($d.reset_time) { $d.reset_time } else { $d.reset_date }
            if ($u -and $tot) {
                $rstInfo = if ($rst) { " · 重置: $rst" } else { "" }
                Write-Host "[po0fw] #$idx [$short…] 📊 流量: $u / $tot$rstInfo"
            }
        }
    } catch {}
}
if ($fail) { exit 1 }