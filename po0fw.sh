#!/bin/sh
# po0fw - GGY (咕咕云) 防火墙自动加白（PC / 软路由 / Termux 通用版）
# https://github.com/w0ven/po0fw
#
# 用法:
#   PO0FW_TOKENS="你的token或完整链接" ./po0fw.sh          # 环境变量方式
#   ./po0fw.sh token1,token2                             # 参数方式（多 token 逗号分割）
#   ./po0fw.sh status                                    # 检查/加白状态
#
# 配置文件（可选，优先级低于环境变量/参数）: /etc/po0fw.conf 内容示例:
#   PO0FW_TOKENS="你的token"
#
# API 说明: 使用咕咕云智简魔方插件白名单分享链接。
#   GET https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=<token>
#
# 注意事项:
#   如果本机运行了代理/软路由，请确保 www.guguyun.com 配置为直连 (DIRECT)，
#   避免将代理节点的落地 IP 加入安全组白名单。

set -u

API_BASE="${PO0FW_API:-https://www.guguyun.com/cany_tencentecs/firewall/whitelist}"
CONF="${PO0FW_CONF:-/etc/po0fw.conf}"
CURL_OPTS="-4sS -m 20 --retry 2 --retry-delay 2 -H Accept:application/json"

MODE="add"
ARG_TOKENS=""
case "${1:-}" in
  status)
    MODE="status"
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
  short=$(echo "$tok" | cut -c1-12)

  url="${API_BASE}?token=${tok}"
  res=$(curl $CURL_OPTS -X GET "$url" 2>&1)

  status=$(echo "$res" | sed -n 's/.*"status":\([0-9]*\).*/\1/p')
  msg=$(echo "$res" | sed -n 's/.*"msg":"\([^"]*\)".*/\1/p')

  if [ "$status" = "200" ]; then
    log "#$IDX [${short}…] ✅ 加白成功: ${msg:-OK}"
  else
    log "#$IDX [${short}…] ❌ 加白失败 (status=${status:-error}): ${msg:-$res}"
    FAIL=1
  fi
  IFS=','
done
IFS=$OLDIFS

exit $FAIL
