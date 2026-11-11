#requires -Version 5.1
# po0fw - GGY (咕咕云) 防火墙自动加白 (Windows)
# 用法: powershell -File po0fw.ps1 -Tokens "token1,token2"
param(
    [string]$Tokens = $env:PO0FW_TOKENS,
    [string]$ApiBase = "https://www.guguyun.com/cany_tencentecs/firewall/whitelist",
    [switch]$Status
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
    $short = $tok.Substring(0, [Math]::Min(12, $tok.Length))
    
    $url = "$ApiBase`?token=$tok"
    try {
        $res = Invoke-RestMethod -Method Get -Uri $url -TimeoutSec 20 -Headers @{ "Accept" = "application/json" }
    } catch {
        Write-Host "[po0fw] #$idx [$short…] ❌ 请求异常: $_"
        $fail = $true
        continue
    }

    $resStatus = $res.status
    $msg = $res.msg
    if ($resStatus -eq 200) {
        Write-Host "[po0fw] #$idx [$short…] ✅ 加白成功: $msg"
    } else {
        Write-Host "[po0fw] #$idx [$short…] ❌ 加白失败 (status=$resStatus): $msg"
        $fail = $true
    }
}
if ($fail) { exit 1 }
