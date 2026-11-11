#!/bin/sh
# po0fw - GGY (咕咕云) 防火墙自动加白与流量查询（PC / 软路由 / Termux 通用版）
# https://github.com/schwarzgelben/ggyfw
#
# 用法:
#   PO0FW_TOKENS="你的token或完整链接" ./po0fw.sh          # 环境变量方式
#   ./po0fw.sh token1,token2                             # 参数方式（多 token 逗号分割）
#   ./po0fw.sh status                                    # 检查/加白状态
#   ./po0fw.sh traffic                                   # 单独查询流量
#
# 槽位支持:
#   在 token 末尾追加 @0~@4（固定槽位）或 @rotate（轮流写入 0~4 槽）
#   或设置环境变量 PO0FW_SLOT="0" 或 PO0FW_SLOT="rotate"
#
# 配置文件（可选，优先级低于环境变量/参数）: /etc/po0fw.conf 内容示例:
#   PO0FW_TOKENS="你的token"
#   PO0FW_SLOT="0"
#
# API 说明: 使用咕咕云智简魔方插件白名单分享链接与流量查询接口。
#   加白: GET https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=<token>
#   流量: GET https://www.guguyun.com/cany_tencentecs/traffic/query?token=<token>
#
# 注意事项:
#   如果本机运行了代理/软路由，请确保 www.guguyun.com 配置为直连 (DIRECT)，
#   避免将代理节点的落地 IP 加入安全组白名单。

set -u

API_BASE="${PO0FW_API:-https://www.guguyun.com/cany_tencentecs/firewall/whitelist}"
TRAFFIC_API_BASE="${PO0FW_TRAFFIC_API:-https://www.guguyun.com/cany_tencentecs/traffic/query}"
CONF="${PO0FW_CONF:-/etc/po0fw.conf}"
SLOT_ARG="${PO0FW_SLOT:-}"

# 默认使用手机 UA：在固定槽位下使软路由/Linux 获得 /24 大网段放行福利（防宽带重拨断流）
PO0FW_UA="${PO0FW_UA:-mobile}"
if [ "$PO0FW_UA" = "pc" ]; then
  USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
else
  USER_AGENT="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
fi

CURL_OPTS="-4sS -m 20 --retry 2 --retry-delay 2 -H Accept:application/json -A $USER_AGENT"

MODE="add"
ARG_TOKENS=""
case "${1:-}" in
  status)
    MODE="status"
    ARG_TOKENS="${2:-}"
    ;;
  traffic)
    MODE="traffic"
    ARG_TOKENS="${2:-}"
    ;;
  "") ;;
  *) ARG_TOKENS="$1" ;;
esac

# token 来源优先级: 命令行参数 > 环境变量 > 配置文件
TOKENS="${ARG_TOKENS:-${PO0FW_TOKENS:-}}"
if [ -z "$TOKENS" ] && [ -f "$CONF" ]; then
  # shellcheck disable=SC1090
  . "$CONF"
  TOKENS="${PO0FW_TOKENS:-}"
  [ -z "$SLOT_ARG" ] && SLOT_ARG="${PO0FW_SLOT:-}"
fi
if [ -z "$TOKENS" ]; then
  echo "po0fw: 未配置 token。请设置 PO0FW_TOKENS 或写入 $CONF" >&2
  exit 1
fi

log() { echo "[po0fw] $*"; }

extract_token() {
  case "$1" in
    *token=*)
      echo "$1" | sed -n 's/.*token=\([^&#]*\).*/\1/p'
      ;;
    *)
      case "$1" in
        http://*|https://*) echo "" ;;
        *) echo "$1" ;;
      esac
      ;;
  esac
}

FAIL=0
IDX=0
OLDIFS=$IFS; IFS=','
for entry in $TOKENS; do
  IFS=$OLDIFS
  IDX=$((IDX+1))
  entry=$(echo "$entry" | tr -d ' ')
  [ -z "$entry" ] && continue
  
  tok=$(extract_token "$entry")
  [ -z "$tok" ] && continue

  # 槽位处理：若自身无 @ 且配置了 SLOT_ARG
  case "$tok" in
    *@*) ;;
    *)
      if [ -n "$SLOT_ARG" ]; then
        tok="${tok}@${SLOT_ARG}"
      fi
      ;;
  esac

  # 提取基础 token（用于查询流量）
  base_tok=$(echo "$tok" | sed 's/@[^@]*$//')
  short=$(echo "$base_tok" | cut -c1-12)
  slot_hint=""
  case "$tok" in
    *@*) slot_hint=" @$(echo "$tok" | sed 's/.*@//')" ;;
  esac

  if [ "$MODE" != "traffic" ]; then
    url="${API_BASE}?token=${tok}"
    res=$(curl $CURL_OPTS -X GET "$url" 2>&1)

    status=$(echo "$res" | sed -n 's/.*"status":\([0-9]*\).*/\1/p')
    msg=$(echo "$res" | sed -n 's/.*"msg":"\([^"]*\)".*/\1/p')

    if [ "$status" = "200" ]; then
      log "#$IDX [${short}…${slot_hint}] ✅ 加白成功: ${msg:-OK}"
    else
      log "#$IDX [${short}…] ❌ 加白失败 (status=${status:-error}): ${msg:-$res}"
      FAIL=1
    fi
  fi

  # 查询流量信息（使用纯净 base_tok）
  turl="${TRAFFIC_API_BASE}?token=${base_tok}"
  tres=$(curl $CURL_OPTS -X GET "$turl" 2>/dev/null || true)
  tstatus=$(echo "$tres" | sed -n 's/.*"status":\([0-9]*\).*/\1/p')
  if [ "$tstatus" = "200" ]; then
    tused_gb=$(echo "$tres" | sed -n 's/.*"used_gb":\([0-9.]*\).*/\1/p')
    ttotal_gb=$(echo "$tres" | sed -n 's/.*"total_gb":\([0-9.]*\).*/\1/p')
    trem_gb=$(echo "$tres" | sed -n 's/.*"remaining_gb":\([0-9.]*\).*/\1/p')
    tunlimited=$(echo "$tres" | sed -n 's/.*"unlimited":\([a-z]*\).*/\1/p')
    treset=$(echo "$tres" | sed -n 's/.*"reset_\(time\|date\)":"\([^"]*\)".*/\2/p')

    if [ -n "$tused_gb" ] && [ -n "$ttotal_gb" ]; then
      u_disp=$(printf "%.2f" "$tused_gb" 2>/dev/null || echo "$tused_gb")
      tot_disp=$(printf "%.0f" "$ttotal_gb" 2>/dev/null || echo "$ttotal_gb")
      rem_disp=""
      [ -n "$trem_gb" ] && rem_disp=" · 余 $(printf "%.1f" "$trem_gb" 2>/dev/null || echo "$trem_gb") GB"
      [ "$tunlimited" = "true" ] && tot_disp="无限" && rem_disp=""
      log "#$IDX [${short}…] 📊 流量: ${u_disp} GB / ${tot_disp} GB${rem_disp}${treset:+ · 重置: $treset}"
    else
      tused=$(echo "$tres" | sed -n 's/.*"used":"\([^"]*\)".*/\1/p')
      ttotal=$(echo "$tres" | sed -n 's/.*"total":"\([^"]*\)".*/\1/p')
      if [ -n "$tused" ] && [ -n "$ttotal" ]; then
        log "#$IDX [${short}…] 📊 流量: ${tused} / ${ttotal}${treset:+ · 重置: $treset}"
      fi
    fi
  fi

  IFS=','
done
IFS=$OLDIFS

exit $FAIL
