#!/bin/sh
set -eu

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/po0fw-test.XXXXXX")
trap 'rm -rf "$TEST_TMP"' EXIT HUP INT TERM

mkdir -p "$TEST_TMP/bin"
cat > "$TEST_TMP/bin/curl" <<'EOF'
#!/bin/sh
printf '%s\n' '{"status":200,"msg":"添加白名单成功","data":[]}'
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

echo 'po0fw shell tests passed'
