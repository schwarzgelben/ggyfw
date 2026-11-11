/*
 * GGY (咕咕云) 防火墙自动加白 · Egern 原生脚本
 *
 * 行为：GET https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=<token>
 * 调用咕咕云魔方插件白名单链接，将当前出口 IP 加入安全组白名单。
 *
 * 注意：必须配置直连规则 domain: www.guguyun.com -> DIRECT
 */

const API_BASE = "https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=";
const STORE_PREFIX = "ggy_fw_";

function extractToken(raw) {
  if (!raw) return "";
  const s = String(raw).trim();
  const m = s.match(/[?&]token=([^&#\s]+)/);
  if (m && m[1]) return decodeURIComponent(m[1]);
  if (/^https?:\/\//i.test(s)) return "";
  return s;
}

function parseTokens(raw) {
  return String(raw || "")
    .split(/[,|;、\r\n\s]+/)
    .map(function (s) {
      return extractToken(s);
    })
    .filter(function (s) {
      return (
        s.length > 0 &&
        s !== "在此填入token" &&
        s.indexOf("你的token") === -1
      );
    });
}

function onCellular(ctx) {
  try {
    const d = ctx.device || {};
    const onWifi = !!(d.wifi && d.wifi.ssid);
    const hasCell = !!(d.cellular && (d.cellular.carrier || d.cellular.radio));
    return !onWifi && hasCell;
  } catch (e) {
    return false;
  }
}

function sleep(ms) {
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

const HTTP_RETRY = 3;
const HTTP_RETRY_DELAY_MS = 1500;

async function httpGetOnce(ctx, url) {
  let text = "";
  let status = 0;
  try {
    const resp = await ctx.http.get(url, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        Accept: "application/json, text/plain, */*",
      },
      timeout: 15000,
    });
    status = resp.status;
    try {
      text = await resp.text();
    } catch (e) {}
  } catch (e) {
    const msg = String((e && e.message) || e);
    const m = msg.match(/status:\s*(\d{3})(?:\s*,\s*body:\s*([\s\S]*))?/i);
    if (m) {
      status = parseInt(m[1], 10);
      text = m[2] !== undefined ? m[2] : "";
    } else {
      return { netError: msg || "网络请求失败（超时 / 握手失败 / 被拦截）" };
    }
  }
  return { status: status, text: text };
}

async function apiCall(ctx, token) {
  const url = API_BASE + encodeURIComponent(token);
  let r = null;
  for (let attempt = 1; attempt <= HTTP_RETRY; attempt++) {
    r = await httpGetOnce(ctx, url);
    if (!r.netError) {
      try {
        const j = JSON.parse(r.text);
        if (j.status === 400) break; // 业务错误不重试
      } catch (e) {}
      if (r.status >= 200 && r.status < 500) break;
    }
    if (attempt < HTTP_RETRY) await sleep(HTTP_RETRY_DELAY_MS * attempt);
  }
  if (r.netError) return { applied: false, error: r.netError + "（已重试 " + HTTP_RETRY + " 次）" };

  let data = null;
  try {
    data = JSON.parse(r.text);
  } catch (e) {}

  if (!data) return { applied: false, error: "响应非 JSON: " + String(r.text).slice(0, 80) };

  if (data.status === 200) {
    return { applied: true, msg: data.msg || "加白成功" };
  } else {
    return { applied: false, error: data.msg || ("加白失败 (状态 " + data.status + ")") };
  }
}

export default async function (ctx) {
  const tokens = parseTokens(ctx.env && ctx.env.tokens);
  if (tokens.length === 0) {
    ctx.notify({
      title: "GGY 防火墙加白",
      subtitle: "未配置 token",
      body: "模块参数 tokens 填入咕咕云 token 或分享链接，多个用英文逗号分割",
    });
    return;
  }

  const cellular = onCellular(ctx);
  const results = [];
  for (let i = 0; i < tokens.length; i++) {
    const st = await apiCall(ctx, tokens[i]);
    results.push({ token: tokens[i], st: st, kvState: STORE_PREFIX + i });
  }

  let okCount = 0;
  let changed = false;
  const lines = [];
  for (let i = 0; i < results.length; i++) {
    const item = results[i];
    const st = item.st;
    if (st.applied) okCount++;
    const short = item.token.length > 12 ? item.token.slice(0, 10) + "…" : item.token;
    lines.push("#" + (i + 1) + " [" + short + "] " + (st.applied ? "✅ " + st.msg : "❌ " + st.error));

    const state = (st.applied ? "1" : "0") + "|" + (st.msg || st.error || "");
    if (ctx.storage.get(item.kvState) !== state) {
      ctx.storage.set(item.kvState, state);
      changed = true;
    }
  }

  const title =
    "GGY 加白 " + okCount + "/" + results.length + (cellular ? " 📶 移动网络" : " 🌐 Wi-Fi");
  if (changed || okCount < results.length) {
    ctx.notify({ title: "GGY 防火墙加白", subtitle: title, body: lines.join("\n") });
  }
}
