/*
 * GGY (咕咕云) 防火墙自动加白 · Egern 原生脚本
 *
 * 行为：GET https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=<token>
 * 调用咕咕云魔方插件白名单链接，将当前出口 IP 加入安全组白名单。
 *
 * 智能探活与自愈机制（方案 1）：
 * 1. 模拟手机 UA：固定槽位链接放行整段 /24。
 * 2. 直连嗅探公网出口 IP。
 * 3. 同 C 段 (/24) 智能节流跳过重复调用。
 * 4. 越界自愈与保活上报。
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

async function httpGetOnce(ctx, url, headers) {
  let text = "";
  let status = 0;
  try {
    const resp = await ctx.http.get(url, {
      headers: headers || {
        "User-Agent":
          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        Accept: "application/json, text/plain, */*",
      },
      timeout: 10000,
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

function isValidIPv4(ip) {
  return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip);
}

function extractIPv4(text) {
  if (!text) return "";
  const s = String(text).trim();
  const mTrace = s.match(/(?:^|\n)ip=([0-9.]+)/);
  if (mTrace && mTrace[1]) {
    const traceIp = mTrace[1].trim();
    if (isValidIPv4(traceIp)) return traceIp;
  }
  const m = s.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/);
  if (m && m[0]) {
    if (m[0] !== "1.1.1.1" && m[0] !== "1.0.0.1" && m[0] !== "8.8.8.8" && m[0] !== "127.0.0.1") {
      return m[0];
    }
  }
  return "";
}

function sameC24(ip1, ip2) {
  if (!ip1 || !ip2) return false;
  const s1 = String(ip1).trim();
  const s2 = String(ip2).trim();
  const seg1 = s1.split(".");
  const seg2 = s2.split(".");
  if (seg1.length !== 4 || seg2.length !== 4) return false;
  return seg1[0] === seg2[0] && seg1[1] === seg2[1] && seg1[2] === seg2[2];
}

function getCSubnet(ip) {
  if (!ip) return "";
  const seg = String(ip).trim().split(".");
  if (seg.length !== 4) return ip;
  return `${seg[0]}.${seg[1]}.${seg[2]}.0/24`;
}

async function detectPublicIp(ctx) {
  const probeUrls = [
    "http://ip.3322.net",
    "http://api-ipv4.ip.sb/ip",
    "http://myip.ipip.net",
    "https://1.1.1.1/cdn-cgi/trace"
  ];
  for (const url of probeUrls) {
    try {
      const r = await httpGetOnce(ctx, url, { "User-Agent": "curl/7.88.1" });
      if (!r.netError && r.text) {
        const ip = extractIPv4(r.text);
        if (ip) return ip;
      }
    } catch (e) {}
  }
  return "";
}

async function apiCall(ctx, token, uaMode) {
  const url = API_BASE + encodeURIComponent(token);
  const userAgent =
    uaMode && uaMode.toLowerCase() === "pc"
      ? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
      : "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";

  let r = null;
  for (let attempt = 1; attempt <= HTTP_RETRY; attempt++) {
    r = await httpGetOnce(ctx, url, {
      "User-Agent": userAgent,
      Accept: "application/json, text/plain, */*",
    });
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
  const skipWifi = ctx.env && ctx.env.skip_wifi;
  const currentSSID = (ctx.device && ctx.device.wifi && ctx.device.wifi.ssid) || "";
  if (currentSSID && skipWifi) {
    const skipList = String(skipWifi).split(/[,|;、\s]+/).map(s => s.trim().toLowerCase());
    if (skipList.includes(currentSSID.toLowerCase())) {
      return;
    }
  }

  const tokens = parseTokens(ctx.env && ctx.env.tokens);
  if (tokens.length === 0) {
    ctx.notify({
      title: "GGY 防火墙加白",
      subtitle: "未配置 token",
      body: "模块参数 tokens 填入咕咕云 token 或分享链接，多个用英文逗号分割",
    });
    return;
  }

  const uaMode = (ctx.env && ctx.env.ua) || "mobile";
  const isMobileUa = uaMode.toLowerCase() !== "pc";
  const currentIp = await detectPublicIp(ctx);

  const lastIp = ctx.storage.get(STORE_PREFIX + "last_ip") || "";
  const lastTs = parseInt(ctx.storage.get(STORE_PREFIX + "last_ts") || "0", 10);
  const lastOk = ctx.storage.get(STORE_PREFIX + "last_ok") === "1";
  const now = Date.now();
  const maxAgeMs = (parseInt((ctx.env && ctx.env.interval) || "10", 10) || 10) * 60 * 1000;

  // 智能探活节流：同 /24 且保活期内跳过 API 请求
  if (lastOk && currentIp && lastIp && now - lastTs < maxAgeMs) {
    if (isMobileUa ? sameC24(currentIp, lastIp) : currentIp === lastIp) {
      return; // 静默放行
    }
  }

  const cellular = onCellular(ctx);
  const results = [];
  for (let i = 0; i < tokens.length; i++) {
    const st = await apiCall(ctx, tokens[i], uaMode);
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

  const allOk = okCount === results.length;
  if (allOk) {
    if (currentIp) ctx.storage.set(STORE_PREFIX + "last_ip", currentIp);
    ctx.storage.set(STORE_PREFIX + "last_ts", String(now));
    ctx.storage.set(STORE_PREFIX + "last_ok", "1");
  } else {
    ctx.storage.set(STORE_PREFIX + "last_ok", "0");
  }

  const ipDrift = lastIp && currentIp && (isMobileUa ? !sameC24(currentIp, lastIp) : currentIp !== lastIp);
  const title =
    "GGY 加白 " + okCount + "/" + results.length + (cellular ? " 📶 移动网络" : " 🌐 Wi-Fi");

  let content = lines.join("\n");
  if (currentIp) {
    content += "\n出口 IP: " + currentIp + (isMobileUa ? " (" + getCSubnet(currentIp) + ")" : " (/32)");
  }

  if (changed || ipDrift || !allOk) {
    ctx.notify({
      title: ipDrift ? "GGY 加白 · 网段自愈" : "GGY 防火墙加白",
      subtitle: title,
      body: content,
    });
  }
}
