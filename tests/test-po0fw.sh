#!/bin/sh
set -eu

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/po0fw-test.XXXXXX")
trap 'rm -rf "$TEST_TMP"' EXIT HUP INT TERM

mkdir -p "$TEST_TMP/bin"
cat > "$TEST_TMP/bin/curl" <<'EOF'
#!/bin/sh
case "$*" in
  *traffic/query*)
    printf '%s\n' '{"status":200,"msg":"请求成功","data":{"version":2,"quota_type":"display","unit":"KB","unlimited":false,"used_transfer":2800662,"remaining_transfer":836060138,"total_transfer":838860800,"used_gb":2.670919,"remaining_gb":797.329081,"total_gb":800,"queried_at":"2026-11-11T19:00:05+08:00","cached":false}}'
    ;;
  *)
    printf '%s\n' '{"status":200,"msg":"添加白名单成功","data":[]}'
    ;;
esac
EOF
chmod +x "$TEST_TMP/bin/curl"

run_po0fw() {
  PATH="$TEST_TMP/bin:$PATH" \
    PO0FW_CONF="$TEST_TMP/missing.conf" \
    /bin/sh "$ROOT/po0fw.sh" "$@"
}

add_output=$(run_po0fw 'dummy_ggy_token')
printf '%s\n' "$add_output"
printf '%s\n' "$add_output" | grep -F '✅ 加白成功: 添加白名单成功' >/dev/null
printf '%s\n' "$add_output" | grep -F '📊 流量: 2.67 GB / 800 GB' >/dev/null

traffic_only_output=$(run_po0fw 'ctecstr_dummy_traffic')
printf '%s\n' "$traffic_only_output"
printf '%s\n' "$traffic_only_output" | grep -F '📊 流量: 2.67 GB / 800 GB' >/dev/null

mixed_output=$(run_po0fw 'dummy_ggy_token,ctecstr_dummy_traffic')
printf '%s\n' "$mixed_output"
printf '%s\n' "$mixed_output" | grep -F '✅ 加白成功: 添加白名单成功' >/dev/null
printf '%s\n' "$mixed_output" | grep -F '📊 流量: 2.67 GB / 800 GB' >/dev/null

echo 'po0fw shell tests passed'
