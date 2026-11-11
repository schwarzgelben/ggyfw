#requires -Version 5.1
# po0fw - GGY (咕咕云) 防火墙自动加白与流量查询 (Windows)
# 用法: powershell -File po0fw.ps1 -Tokens "token1,token2" [-Slot "0"]
param(
    [string]$Tokens = $env:PO0FW_TOKENS,
    [string]$TrafficTokens = $env:PO0FW_TRAFFIC_TOKENS,
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

    # 查询流量信息（使用纯净 baseTok 或独立指定 TrafficTokens）
    $targetTrafficTok = $baseTok
    if ($TrafficTokens) {
        $tList = $TrafficTokens -split '[,;|\s]+' | Where-Object { $_ -ne "" }
        if ($tList.Count -ge $idx) {
            $rawT = $tList[$idx - 1]
            if ($rawT -match '[?&]token=([^&#\s]+)') { $rawT = $matches[1] }
            $targetTrafficTok = $rawT -replace '[@%].*$', ''
        }
    }
    $tUrl = "$TrafficApiBase`?token=$targetTrafficTok"
    try {
        $tRes = Invoke-RestMethod -Method Get -Uri $tUrl -TimeoutSec 10 -Headers @{ "Accept" = "application/json"; "User-Agent" = $userAgent }
        if ($tRes.status -eq 200 -and $tRes.data) {
            $d = $tRes.data
            $uGb = if ($d.used_gb -ne $null) { [math]::Round([double]$d.used_gb, 2) } elseif ($d.used_transfer -ne $null) { [math]::Round([double]$d.used_transfer / 1048576, 2) } else { $null }
            $totGb = if ($d.total_gb -ne $null) { [math]::Round([double]$d.total_gb, 1) } elseif ($d.total_transfer -ne $null) { [math]::Round([double]$d.total_transfer / 1048576, 1) } else { $null }
            $remGb = if ($d.remaining_gb -ne $null) { [math]::Round([double]$d.remaining_gb, 1) } elseif ($d.remaining_transfer -ne $null) { [math]::Round([double]$d.remaining_transfer / 1048576, 1) } else { $null }
            $rst = if ($d.reset_time) { $d.reset_time } elseif ($d.reset_date) { $d.reset_date } else { $null }
            $rstInfo = if ($rst) { " · 重置: $rst" } else { "" }

            if ($uGb -ne $null -and ($totGb -ne $null -or $d.unlimited -eq $true)) {
                $totStr = if ($d.unlimited -eq $true) { "无限" } else { "${totGb} GB" }
                $pct = if ($totGb -and $totGb -gt 0 -and $d.unlimited -ne $true) { " (" + [math]::Round(($uGb / $totGb) * 100, 1) + "%)" } else { "" }
                $remStr = if ($remGb -ne $null -and $d.unlimited -ne $true) { " · 余 ${remGb} GB" } else { "" }
                Write-Host "[po0fw] #$idx [$short…] 📊 流量: ${uGb} GB / ${totStr}${pct}${remStr}${rstInfo}"
            } else {
                $u = if ($d.used) { $d.used } else { $d.traffic_used }
                $tot = if ($d.total) { $d.total } else { $d.traffic_total }
                if ($u -and $tot) {
                    Write-Host "[po0fw] #$idx [$short…] 📊 流量: $u / $tot$rstInfo"
                }
            }
        }
    } catch {}
}
if ($fail) { exit 1 }