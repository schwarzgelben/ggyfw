/*
 * GGY (咕咕云) 防火墙自动加白与流量查询 · Egern 原生脚本
 *
 * 加白：GET https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=<token>
 * 流量：GET https://www.guguyun.com/cany_tencentecs/traffic/query?token=<token>
 *
 * 槽位支持：
 * 1. 固定槽位：token@0 ~ token@4 或参数 slot=0
 * 2. 轮流写入：token@rotate 或参数 slot=rotate
 */

const API_BASE = "https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=";
const TRAFFIC_API_BASE = "https://www.guguyun.com/cany_tencentecs/traffic/query?token=";
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
    if (m[0] !== "1.1.1.1" && m[0] !== "1.0.0.1" && m[0] !== "8.8.8.8" && m[0] !== "127.0.0.1" && m[0] !== "0.0.0.0") {
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

function parseSlotConfig(tokenStr, globalSlotArg) {
  let baseToken = tokenStr;
  let slotMode = "";
  let fixedSlot = 0;
  let rotateSlots = [0, 1, 2, 3, 4];

  const atIdx = tokenStr.lastIndexOf("@");
  if (atIdx !== -1) {
    baseToken = tokenStr.slice(0, atIdx).trim();
    const atVal = tokenStr.slice(atIdx + 1).trim().toLowerCase();
    if (/^\d+$/.test(atVal)) {
      slotMode = "fixed";
      fixedSlot = parseInt(atVal, 10);
    } else if (atVal === "rotate" || atVal === "auto") {
      slotMode = "rotate";
      rotateSlots = [0, 1, 2, 3, 4];
    } else if (/^(\d+)-(\d+)$/.test(atVal)) {
      const mRange = atVal.match(/^(\d+)-(\d+)$/);
      const start = parseInt(mRange[1], 10);
      const end = parseInt(mRange[2], 10);
      rotateSlots = [];
      for (let r = Math.min(start, end); r <= Math.max(start, end); r++) rotateSlots.push(r);
      slotMode = "rotate";
    }
  }

  if (!slotMode && globalSlotArg) {
    const g = String(globalSlotArg).trim().toLowerCase();
    if (/^\d+$/.test(g)) {
      slotMode = "fixed";
      fixedSlot = parseInt(g, 10);
    } else if (g === "rotate" || g === "auto") {
      slotMode = "rotate";
      rotateSlots = [0, 1, 2, 3, 4];
    } else if (/^(\d+)-(\d+)$/.test(g)) {
      const mG = g.match(/^(\d+)-(\d+)$/);
      const sG = parseInt(mG[1], 10);
      const eG = parseInt(mG[2], 10);
      rotateSlots = [];
      for (let j = Math.min(sG, eG); j <= Math.max(sG, eG); j++) rotateSlots.push(j);
      slotMode = "rotate";
    }
  }

  return { baseToken, slotMode, fixedSlot, rotateSlots };
}

function resolveActualToken(ctx, rawToken, index, globalSlotArg) {
  const cfg = parseSlotConfig(rawToken, globalSlotArg);
  const pointerKey = STORE_PREFIX + "slot_ptr_" + index;
  let currentPtr = parseInt(ctx.storage.get(pointerKey) || "0", 10);
  if (isNaN(currentPtr) || currentPtr < 0 || currentPtr >= cfg.rotateSlots.length) {
    currentPtr = 0;
  }

  let actualToken = cfg.baseToken;
  let slotLabel = "";
  let activeSlot = null;

  if (cfg.slotMode === "fixed") {
    actualToken = `${cfg.baseToken}@${cfg.fixedSlot}`;
    slotLabel = `@${cfg.fixedSlot}`;
    activeSlot = cfg.fixedSlot;
  } else if (cfg.slotMode === "rotate") {
    activeSlot = cfg.rotateSlots[currentPtr];
    actualToken = `${cfg.baseToken}@${activeSlot}`;
    slotLabel = `@${activeSlot}(轮换)`;
  }

  return {
    raw: rawToken,
    baseToken: cfg.baseToken,
    actualToken: actualToken,
    slotMode: cfg.slotMode,
    slotLabel: slotLabel,
    activeSlot: activeSlot,
    currentPtr: currentPtr,
    rotateSlots: cfg.rotateSlots,
    pointerKey: pointerKey,
  };
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

function formatTrafficBytes(val, unit) {
  if (val === null || val === undefined || val === "") return "";
  if (typeof val === "string") {
    val = val.trim();
    if (/[a-zA-Z]/.test(val)) return val;
    const num = parseFloat(val);
    if (isNaN(num)) return val;
    val = num;
  }
  if (typeof val === "number") {
    if (unit) {
      const u = unit.toUpperCase();
      if (u === "GB" || u === "G") return val.toFixed(1) + " GB";
      if (u === "MB" || u === "M") return (val >= 1024 ? (val / 1024).toFixed(1) + " GB" : val.toFixed(1) + " MB");
      if (u === "TB" || u === "T") return val.toFixed(2) + " TB";
    }
    if (val >= 1099511627776) return (val / 1099511627776).toFixed(2) + " TB";
    if (val >= 1073741824) return (val / 1073741824).toFixed(2) + " GB";
    if (val >= 1048576) return (val / 1048576).toFixed(2) + " MB";
    if (val > 0 && val < 100000) return val.toFixed(1) + " GB";
    return String(val);
  }
  return String(val);
}

function parseTrafficData(data) {
  if (!data) return null;
  if (Array.isArray(data)) {
    if (data.length === 0) return null;
    data = data[0];
  }
  if (typeof data !== "object") return { line: String(data) };
  if (data.traffic && typeof data.traffic === "object") data = data.traffic;

  const unit = data.unit || data.traffic_unit || "";

  const rawUsed = data.used !== undefined ? data.used :
                 (data.traffic_used !== undefined ? data.traffic_used :
                 (data.used_traffic !== undefined ? data.used_traffic :
                 (data.use !== undefined ? data.use :
                 (data.traffic_out !== undefined ? data.traffic_out :
                 (data.out !== undefined ? data.out : null)))));

  const rawTotal = data.total !== undefined ? data.total :
                  (data.traffic_total !== undefined ? data.traffic_total :
                  (data.total_traffic !== undefined ? data.total_traffic :
                  (data.limit !== undefined ? data.limit :
                  (data.max !== undefined ? data.max :
                  (data.bandwidth !== undefined ? data.bandwidth : null)))));

  const rawRest = data.rest !== undefined ? data.rest :
                 (data.traffic_rest !== undefined ? data.traffic_rest :
                 (data.remaining !== undefined ? data.remaining :
                 (data.traffic_remaining !== undefined ? data.traffic_remaining :
                 (data.left !== undefined ? data.left : null))));

  const rawReset = data.reset_date !== undefined ? data.reset_date :
                  (data.reset_time !== undefined ? data.reset_time :
                  (data.traffic_reset !== undefined ? data.traffic_reset :
                  (data.next_reset !== undefined ? data.next_reset :
                  (data.reset_day !== undefined ? "每月 " + data.reset_day + " 日" :
                  (data.reset !== undefined ? data.reset : null)))));

  const usedStr = formatTrafficBytes(rawUsed, unit);
  const totalStr = formatTrafficBytes(rawTotal, unit);
  const restStr = formatTrafficBytes(rawRest, unit);

  let percentStr = "";
  if (data.percent !== undefined) {
    percentStr = String(data.percent);
    if (!percentStr.includes("%")) percentStr += "%";
  } else if (rawUsed !== null && rawTotal !== null) {
    const uNum = parseFloat(String(rawUsed));
    const tNum = parseFloat(String(rawTotal));
    if (!isNaN(uNum) && !isNaN(tNum) && tNum > 0) {
      percentStr = ((uNum / tNum) * 100).toFixed(1) + "%";
    }
  }

  let line = "";
  if (usedStr && totalStr) {
    line = "流量: " + usedStr + " / " + totalStr + (percentStr ? " (" + percentStr + ")" : "");
  } else if (restStr && totalStr) {
    line = "流量: 余 " + restStr + " / 共 " + totalStr;
  } else if (usedStr) {
    line = "已用: " + usedStr;
  } else if (restStr) {
    line = "剩余: " + restStr;
  }

  if (rawReset) {
    const resetStr = String(rawReset).replace(/^\d{4}-/, "").replace(/\s.*$/, "");
    if (resetStr) {
      if (line) line += " · " + resetStr + " 重置";
      else line = "重置: " + resetStr;
    }
  }

  return { line: line, used: usedStr, total: totalStr, rest: restStr, reset: rawReset };
}

async function queryTraffic(ctx, baseToken, index, multi) {
  const kvKey = STORE_PREFIX + "traffic_" + index;
  const kvTsKey = STORE_PREFIX + "traffic_ts_" + index;

  const cached = ctx.storage.get(kvKey) || "";
  const cachedTs = parseInt(ctx.storage.get(kvTsKey) || "0", 10);
  const now = Date.now();
  const CACHE_TTL = 5 * 60 * 1000;

  if (cached && now - cachedTs < CACHE_TTL) {
    return cached;
  }

  const url = TRAFFIC_API_BASE + encodeURIComponent(baseToken);
  const r = await httpGetOnce(ctx, url, {
    "User-Agent":
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    Accept: "application/json, text/plain, */*",
  });

  if (r.netError) return cached;
  let data = null;
  try {
    const j = JSON.parse(r.text);
    if (j && (j.status === 200 || j.code === 200) && j.data) {
      data = j.data;
    }
  } catch (e) {}

  if (!data) return cached;
  const parsed = parseTrafficData(data);
  if (parsed && parsed.line) {
    const prefix = multi ? "📊 #" + (index + 1) + " " : "📊 ";
    const line = prefix + parsed.line;
    ctx.storage.set(kvKey, line);
    ctx.storage.set(kvTsKey, String(now));
    return line;
  }
  return cached;
}

async function apiCall(ctx, actualToken, uaMode) {
  const url = API_BASE + encodeURIComponent(actualToken);
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

  const globalSlot = (ctx.env && ctx.env.slot) || "";
  const tokenItems = tokens.map((t, i) => resolveActualToken(ctx, t, i, globalSlot));

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
  const trafficLines = [];
  for (let i = 0; i < tokenItems.length; i++) {
    const item = tokenItems[i];
    const st = await apiCall(ctx, item.actualToken, uaMode);
    results.push({ item: item, st: st, kvState: STORE_PREFIX + i });
    const traf = await queryTraffic(ctx, item.baseToken, i, tokenItems.length > 1);
    if (traf) trafficLines.push(traf);
  }

  let okCount = 0;
  let changed = false;
  const lines = [];
  for (let i = 0; i < results.length; i++) {
    const res = results[i];
    const item = res.item;
    const st = res.st;
    if (st.applied) okCount++;
    const short = item.baseToken.length > 12 ? item.baseToken.slice(0, 10) + "…" : item.baseToken;
    lines.push("#" + (i + 1) + " [" + short + (item.slotLabel ? " " + item.slotLabel : "") + "] " + (st.applied ? "✅ " + st.msg : "❌ " + st.error));

    const state = (st.applied ? "1" : "0") + "|" + (st.msg || st.error || "");
    if (ctx.storage.get(res.kvState) !== state) {
      ctx.storage.set(res.kvState, state);
      changed = true;
    }
  }

  const allOk = okCount === results.length;
  const ipDrift = lastIp && currentIp && (isMobileUa ? !sameC24(currentIp, lastIp) : currentIp !== lastIp);

  if (allOk) {
    if (currentIp) ctx.storage.set(STORE_PREFIX + "last_ip", currentIp);
    ctx.storage.set(STORE_PREFIX + "last_ts", String(now));
    ctx.storage.set(STORE_PREFIX + "last_ok", "1");

    if (ipDrift || !lastIp) {
      tokenItems.forEach(it => {
        if (it.slotMode === "rotate") {
          const nextPtr = (it.currentPtr + 1) % it.rotateSlots.length;
          ctx.storage.set(it.pointerKey, String(nextPtr));
        }
      });
    }
  } else {
    ctx.storage.set(STORE_PREFIX + "last_ok", "0");
  }

  const title =
    "GGY 加白 " + okCount + "/" + results.length + (cellular ? " 📶 移动网络" : " 🌐 Wi-Fi");

  let content = lines.join("\n");
  if (trafficLines.length > 0) {
    content += "\n" + trafficLines.join("\n");
  }
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
