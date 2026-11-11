/*
 * GGY (咕咕云) 防火墙白名单自动加白与流量查询
 * 兼容：Surge / Stash / Shadowrocket / Loon / Quantumult X
 *
 * 加白端点：GET https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=<token>
 * 流量端点：GET https://www.guguyun.com/cany_tencentecs/traffic/query?token=<token>
 *
 * 槽位支持（固定槽位 @0~@4 与轮换写入）：
 * 1. 固定槽位写入：在 token 末尾追加 @0 ~ @4（例如 token@0），或指定参数 slot=0。
 *    每个固定槽位在手机 UA 下放行对应基站的整段 /24 网段。
 * 2. 轮流写入（环形槽位池）：指定 token@rotate（或 token@0-4 / 参数 slot=rotate）。
 *    每次检测到跨基站网段漂移（新 C 段）时，自动轮换写入下一个槽位（0 -> 1 -> 2 -> 3 -> 4 -> 0）。
 *    这使得用户最近经过的 5 个基站网段同时保持加白，多地点往返无缝零断流！
 * 3. 流量查询自动脱敏：查询流量时自动剥离 @0~@4 后缀，保证流量接口稳定命中。
 *
 * 智能探活与自愈机制（方案 1）：
 * 1. 识别手机 UA（ua=mobile，默认）：固定槽位链接放行整段 /24（256个IP）。
 * 2. 轻量公网 IP 嗅探：直连探测本机出口公网 IP（直连 3322.net / ip.sb / ipip.net / 1.1.1.1）。
 * 3. 同 C 段智能节流：若当前出口 IP 与上次加白 IP 处于同一 /24 网段且在保活期内，
 *    判定为安全组已放行，自动跳过咕咕云加白 API 请求（零频次消耗、零断流）。
 * 4. 越界秒级自愈：每 2 分钟高频 cron 探活，一旦检测到基站 IP 跳出 /24 网段，
 *    立即发起咕咕云加白请求，将新网段加入防火墙，实现无感自愈。
 * 5. 手动刷新：点击面板按钮立即强制重新加白并刷新流量与状态。
 *
 * 分流注意：
 * 加白请求、流量查询与 IP 嗅探必须直连！必须配置分流规则：
 * DOMAIN,www.guguyun.com,DIRECT
 * DOMAIN-SUFFIX,3322.net,DIRECT
 * DOMAIN-SUFFIX,ip.sb,DIRECT
 * DOMAIN-SUFFIX,ipip.net,DIRECT
 * IP-CIDR,1.1.1.1/32,DIRECT,no-resolve
 * DOMAIN,1.1.1.1,DIRECT
 */

var INLINE_TOKENS = "";

var API_BASE = "https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=";
var TRAFFIC_API_BASE = "https://www.guguyun.com/cany_tencentecs/traffic/query?token=";
var STORE_PREFIX = "ggy_fw_";
var TOKENS_KEY = "ggy_tokens";
var TOKENS_KEY_LEGACY = "po0fw_tokens";

/* ---------- 环境兼容层 ---------- */

var isQX = typeof $task !== "undefined";
var isSurgeLike = typeof $httpClient !== "undefined"; // Surge/Stash/Shadowrocket/Loon

var envInfo = "";
try {
  if (typeof $environment !== "undefined" && $environment) {
    envInfo = JSON.stringify($environment).toLowerCase();
  }
} catch (e) {}

var isLoon = typeof $loon !== "undefined" || envInfo.indexOf("loon") >= 0;
var isSurgeFamily =
  envInfo.indexOf("surge-version") >= 0 ||
  envInfo.indexOf("shadowrocket") >= 0 ||
  envInfo.indexOf("stash") >= 0;

var REQUEST_TIMEOUT = null;
if (isLoon || isQX) REQUEST_TIMEOUT = 15000;
else if (isSurgeFamily) REQUEST_TIMEOUT = 15;

function storeRead(key) {
  if (isQX) return $prefs.valueForKey(key);
  if (typeof $persistentStore !== "undefined") return $persistentStore.read(key);
  return null;
}

function storeWrite(value, key) {
  if (isQX) return $prefs.setValueForKey(value, key);
  if (typeof $persistentStore !== "undefined") return $persistentStore.write(value, key);
  return false;
}

function notify(title, subtitle, body) {
  if (isQX) $notify(title, subtitle, body);
  else if (typeof $notification !== "undefined") $notification.post(title, subtitle, body);
}

function describeHttpError(error) {
  var text;
  if (error === null || error === undefined) text = "";
  else if (typeof error === "object")
    text = String(error.message || error.error || error.description || "");
  else text = String(error);
  text = text.replace(/^\s+|\s+$/g, "");
  if (text === "" || text === "null" || text === "undefined" || text === "{}") {
    return "网络请求失败（超时 / 握手失败 / 被拦截）";
  }
  return text;
}

function httpRequestOnce(method, opts) {
  return new Promise(function (resolve) {
    if (isQX) {
      opts.method = method;
      $task.fetch(opts).then(
        function (resp) {
          resolve({ body: resp.body, status: resp.statusCode });
        },
        function (err) {
          resolve({ error: describeHttpError((err && err.error) || err) });
        }
      );
    } else if (isSurgeLike) {
      var cb = function (error, response, body) {
        if (error) resolve({ error: describeHttpError(error) });
        else resolve({ body: body, status: response && (response.status || response.statusCode) });
      };
      if (method === "POST") $httpClient.post(opts, cb);
      else $httpClient.get(opts, cb);
    } else {
      resolve({ error: "unsupported client" });
    }
  });
}

function delay(ms) {
  return new Promise(function (resolve) {
    if (typeof setTimeout === "function") setTimeout(resolve, ms);
    else resolve();
  });
}

var HTTP_RETRY = 3;
var HTTP_RETRY_DELAY_MS = 1500;

function isRetryableServerError(r) {
  if (!r || !r.status) return false;
  if (r.status >= 500) return true;
  if (r.status >= 200 && r.status < 300) return false;
  try {
    var j = JSON.parse(r.body);
    if (j && j.status === 400) return false; // 明确业务错误不重试
    return false;
  } catch (e) {
    return true; // 非 JSON 响应属于瞬时网络/反代异常
  }
}

function httpRequest(method, opts, attempt) {
  attempt = attempt || 1;
  return httpRequestOnce(method, opts).then(function (r) {
    if (!r.error && !isRetryableServerError(r)) return r;
    if (attempt >= HTTP_RETRY) {
      if (r.error) r.error = r.error + "（已重试 " + HTTP_RETRY + " 次）";
      return r;
    }
    return delay(HTTP_RETRY_DELAY_MS * attempt).then(function () {
      return httpRequest(method, opts, attempt + 1);
    });
  });
}

function extractToken(raw) {
  if (!raw) return "";
  var s = String(raw).trim();
  // 提取包含 @0~5 或 @rotate 的完整 token
  var m = s.match(/[?&]token=([^&#\s]+)/);
  if (m && m[1]) return decodeURIComponent(m[1]);
  if (/^https?:\/\//i.test(s)) return "";
  return s;
}

function parseArgument() {
  var res = { tokens: "", skip_wifi: "", ua: "mobile", interval: "10", force: "0", slot: "" };
  if (typeof $argument === "undefined" || $argument === null) return res;

  // 1. Loon 数组对象传参: [tokens, skip_wifi, ua, slot]
  if (Array.isArray($argument)) {
    if ($argument[0] !== undefined) res.tokens = String($argument[0]);
    if ($argument[1] !== undefined) res.skip_wifi = String($argument[1]);
    if ($argument[2] !== undefined) res.ua = String($argument[2]);
    if ($argument[3] !== undefined) res.slot = String($argument[3]);
    if ($argument[4] !== undefined) res.interval = String($argument[4]);
    return res;
  }

  // 2. 普通 Object
  if (typeof $argument === "object") {
    if ($argument.tokens !== undefined) res.tokens = String($argument.tokens);
    if ($argument.skip_wifi !== undefined) res.skip_wifi = String($argument.skip_wifi);
    if ($argument.ua !== undefined) res.ua = String($argument.ua);
    if ($argument.interval !== undefined) res.interval = String($argument.interval);
    if ($argument.force !== undefined) res.force = String($argument.force);
    if ($argument.slot !== undefined) res.slot = String($argument.slot);
    return res;
  }

  var raw = String($argument).trim();
  if (/^["'].*["']$/.test(raw)) raw = raw.slice(1, -1).trim();

  // 3. JSON Object 字符串: {"tokens":"..."}
  if (raw.charAt(0) === "{") {
    try {
      var p = JSON.parse(raw);
      if (p) {
        if (p.tokens !== undefined) res.tokens = String(p.tokens);
        if (p.skip_wifi !== undefined) res.skip_wifi = String(p.skip_wifi);
        if (p.ua !== undefined) res.ua = String(p.ua);
        if (p.interval !== undefined) res.interval = String(p.interval);
        if (p.force !== undefined) res.force = String(p.force);
        if (p.slot !== undefined) res.slot = String(p.slot);
        return res;
      }
    } catch (e) {}
  }

  // 4. JSON Array 或中括号语法 (Loon argument=[...]): ["tok", "wifi", "mobile", "rotate"]
  if (raw.charAt(0) === "[") {
    try {
      var arr = JSON.parse(raw);
      if (Array.isArray(arr)) {
        if (arr[0] !== undefined) res.tokens = String(arr[0]);
        if (arr[1] !== undefined) res.skip_wifi = String(arr[1]);
        if (arr[2] !== undefined) res.ua = String(arr[2]);
        if (arr[3] !== undefined) res.slot = String(arr[3]);
        if (arr[4] !== undefined) res.interval = String(arr[4]);
        return res;
      }
    } catch (e) {
      var inner = raw.slice(1, -1).trim();
      var parts = inner.split(",");
      if (parts[0] !== undefined) res.tokens = parts[0].trim();
      if (parts[1] !== undefined) res.skip_wifi = parts[1].trim();
      if (parts[2] !== undefined) res.ua = parts[2].trim();
      if (parts[3] !== undefined) res.slot = parts[3].trim();
      if (parts[4] !== undefined) res.interval = parts[4].trim();
      return res;
    }
  }

  // 5. Query string 语法: tokens=xxx&skip_wifi=yyy&ua=mobile&slot=0
  if (raw.indexOf("=") !== -1) {
    var pairs = raw.split("&");
    var foundKey = false;
    for (var i = 0; i < pairs.length; i++) {
      var eqIdx = pairs[i].indexOf("=");
      if (eqIdx !== -1) {
        var k = pairs[i].slice(0, eqIdx).trim();
        var v = decodeURIComponent(pairs[i].slice(eqIdx + 1).trim());
        if (k === "tokens") { res.tokens = v; foundKey = true; }
        else if (k === "skip_wifi") { res.skip_wifi = v; foundKey = true; }
        else if (k === "ua") { res.ua = v; foundKey = true; }
        else if (k === "interval") { res.interval = v; foundKey = true; }
        else if (k === "force") { res.force = v; foundKey = true; }
        else if (k === "slot") { res.slot = v; foundKey = true; }
      }
    }
    if (foundKey) return res;
  }

  // 6. 单个纯 token 字符串
  res.tokens = raw;
  return res;
}

function getWifiSSID() {
  try {
    if (typeof $network !== "undefined" && $network && $network.wifi && $network.wifi.ssid) {
      return String($network.wifi.ssid);
    }
  } catch (e) {}
  return "";
}

function onCellular() {
  try {
    var iface =
      ($network.v4 && $network.v4.primaryInterface) ||
      ($network.v6 && $network.v6.primaryInterface) ||
      "";
    return iface.indexOf("pdp_ip") === 0;
  } catch (e) {
    return false;
  }
}

function finish(title, content, allOk) {
  if (isQX) {
    $done();
    return;
  }
  $done({
    title: title,
    content: content,
    icon: allOk ? "checkmark.shield" : "exclamationmark.shield",
    "icon-color": allOk ? "#34C759" : "#FF3B30",
  });
}

/* ---------- 公网 IP 探测与网段比较 ---------- */

function isValidIPv4(ip) {
  return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip);
}

function extractIPv4(text) {
  if (!text) return "";
  var s = String(text).trim();

  // 1. 优先针对 1.1.1.1/cdn-cgi/trace 的特定响应：匹配 ip=x.x.x.x，避免误取 h=1.1.1.1
  var mTrace = s.match(/(?:^|\n)ip=([0-9.]+)/);
  if (mTrace && mTrace[1]) {
    var traceIp = mTrace[1].trim();
    if (isValidIPv4(traceIp)) return traceIp;
  }

  // 2. 通用 IPv4 匹配
  var m = s.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/);
  if (m && m[0]) {
    // 排除探测目标服务器本身的 IP
    if (m[0] !== "1.1.1.1" && m[0] !== "1.0.0.1" && m[0] !== "8.8.8.8" && m[0] !== "127.0.0.1" && m[0] !== "0.0.0.0") {
      return m[0];
    }
  }
  return "";
}

function sameC24(ip1, ip2) {
  if (!ip1 || !ip2) return false;
  var s1 = String(ip1).trim();
  var s2 = String(ip2).trim();
  var seg1 = s1.split(".");
  var seg2 = s2.split(".");
  if (seg1.length !== 4 || seg2.length !== 4) return false;
  return seg1[0] === seg2[0] && seg1[1] === seg2[1] && seg1[2] === seg2[2];
}

function getCSubnet(ip) {
  if (!ip) return "";
  var seg = String(ip).trim().split(".");
  if (seg.length !== 4) return ip;
  return seg[0] + "." + seg[1] + "." + seg[2] + ".0/24";
}

function detectPublicIp() {
  var probeUrls = [
    "http://ip.3322.net",
    "http://api-ipv4.ip.sb/ip",
    "http://myip.ipip.net",
    "https://1.1.1.1/cdn-cgi/trace"
  ];
  var probeTimeout = isLoon || isQX ? 4000 : 4;

  function probeAt(idx) {
    if (idx >= probeUrls.length) return Promise.resolve("");
    var targetUrl = probeUrls[idx];
    var opts = {
      url: targetUrl,
      headers: { "User-Agent": "curl/7.88.1" }
    };
    if (REQUEST_TIMEOUT !== null) {
      opts.timeout = probeTimeout;
    }
    return httpRequestOnce("GET", opts)
      .then(function (r) {
        if (!r.error && r.body) {
          var ip = extractIPv4(r.body);
          if (ip) return ip;
        }
        return probeAt(idx + 1);
      })
      .catch(function () {
        return probeAt(idx + 1);
      });
  }

  return probeAt(0);
}

/* ---------- 槽位解析与轮换管理 ---------- */

function parseSlotConfig(tokenStr, globalSlotArg) {
  var baseToken = tokenStr;
  var slotMode = ""; // "" (默认自动轮换/未指定) | "fixed" | "rotate"
  var fixedSlot = 0;
  var rotateSlots = [0, 1, 2, 3, 4];

  // 1. 优先从单个 token 字符串自身解析后缀 @...
  var atIdx = tokenStr.lastIndexOf("@");
  if (atIdx !== -1) {
    baseToken = tokenStr.slice(0, atIdx).trim();
    var atVal = tokenStr.slice(atIdx + 1).trim().toLowerCase();
    if (/^\d+$/.test(atVal)) {
      slotMode = "fixed";
      fixedSlot = parseInt(atVal, 10);
    } else if (atVal === "rotate" || atVal === "auto") {
      slotMode = "rotate";
      rotateSlots = [0, 1, 2, 3, 4];
    } else if (/^(\d+)-(\d+)$/.test(atVal)) {
      var mRange = atVal.match(/^(\d+)-(\d+)$/);
      var start = parseInt(mRange[1], 10);
      var end = parseInt(mRange[2], 10);
      var list = [];
      for (var r = Math.min(start, end); r <= Math.max(start, end); r++) list.push(r);
      slotMode = "rotate";
      rotateSlots = list;
    }
  }

  // 2. 若 token 未显式指定后缀，则遵循全局 slot 参数
  if (!slotMode && globalSlotArg) {
    var g = String(globalSlotArg).trim().toLowerCase();
    if (/^\d+$/.test(g)) {
      slotMode = "fixed";
      fixedSlot = parseInt(g, 10);
    } else if (g === "rotate" || g === "auto") {
      slotMode = "rotate";
      rotateSlots = [0, 1, 2, 3, 4];
    } else if (/^(\d+)-(\d+)$/.test(g)) {
      var mG = g.match(/^(\d+)-(\d+)$/);
      var sG = parseInt(mG[1], 10);
      var eG = parseInt(mG[2], 10);
      var listG = [];
      for (var j = Math.min(sG, eG); j <= Math.max(sG, eG); j++) listG.push(j);
      slotMode = "rotate";
      rotateSlots = listG;
    } else if (g.indexOf(",") !== -1) {
      var parts = g.split(",").map(function (s) { return parseInt(s.trim(), 10); }).filter(function (n) { return !isNaN(n); });
      if (parts.length > 0) {
        slotMode = "rotate";
        rotateSlots = parts;
      }
    }
  }

  return {
    baseToken: baseToken,
    slotMode: slotMode,
    fixedSlot: fixedSlot,
    rotateSlots: rotateSlots,
  };
}

function resolveActualToken(rawToken, index, globalSlotArg, isSubnetDrift) {
  var cfg = parseSlotConfig(rawToken, globalSlotArg);
  var slotKey = STORE_PREFIX + "slot_active_" + index;
  var storedSlot = storeRead(slotKey);

  var actualToken = cfg.baseToken;
  var slotLabel = "";
  var activeSlot = null;

  if (cfg.slotMode === "fixed") {
    activeSlot = cfg.fixedSlot;
    actualToken = cfg.baseToken + "@" + cfg.fixedSlot;
    slotLabel = "@" + cfg.fixedSlot;
  } else if (cfg.slotMode === "rotate") {
    var slotIdx = 0;
    if (storedSlot !== null && storedSlot !== undefined && storedSlot !== "") {
      var lastSlotNum = parseInt(storedSlot, 10);
      var pos = cfg.rotateSlots.indexOf(lastSlotNum);
      if (pos === -1) pos = 0;
      if (isSubnetDrift) {
        pos = (pos + 1) % cfg.rotateSlots.length;
      }
      slotIdx = pos;
    } else {
      slotIdx = 0;
    }
    activeSlot = cfg.rotateSlots[slotIdx];
    actualToken = cfg.baseToken + "@" + activeSlot;
    slotLabel = "@" + activeSlot + "(轮换)";
  }

  return {
    raw: rawToken,
    baseToken: cfg.baseToken,
    actualToken: actualToken,
    slotMode: cfg.slotMode,
    slotLabel: slotLabel,
    activeSlot: activeSlot,
    rotateSlots: cfg.rotateSlots,
    slotKey: slotKey,
  };
}

/* ---------- 流量查询与格式化 ---------- */

function formatTrafficBytes(val, unit) {
  if (val === null || val === undefined || val === "") return "";
  if (typeof val === "string") {
    val = val.trim();
    if (/[a-zA-Z]/.test(val)) return val;
    var num = parseFloat(val);
    if (isNaN(num)) return val;
    val = num;
  }
  if (typeof val === "number") {
    if (unit) {
      var u = unit.toUpperCase();
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

  var unit = data.unit || data.traffic_unit || "";

  var rawUsed = data.used !== undefined ? data.used :
               (data.traffic_used !== undefined ? data.traffic_used :
               (data.used_traffic !== undefined ? data.used_traffic :
               (data.use !== undefined ? data.use :
               (data.traffic_out !== undefined ? data.traffic_out :
               (data.out !== undefined ? data.out : null)))));

  var rawTotal = data.total !== undefined ? data.total :
                (data.traffic_total !== undefined ? data.traffic_total :
                (data.total_traffic !== undefined ? data.total_traffic :
                (data.limit !== undefined ? data.limit :
                (data.max !== undefined ? data.max :
                (data.bandwidth !== undefined ? data.bandwidth : null)))));

  var rawRest = data.rest !== undefined ? data.rest :
               (data.traffic_rest !== undefined ? data.traffic_rest :
               (data.remaining !== undefined ? data.remaining :
               (data.traffic_remaining !== undefined ? data.traffic_remaining :
               (data.left !== undefined ? data.left : null))));

  var rawReset = data.reset_date !== undefined ? data.reset_date :
                (data.reset_time !== undefined ? data.reset_time :
                (data.traffic_reset !== undefined ? data.traffic_reset :
                (data.next_reset !== undefined ? data.next_reset :
                (data.reset_day !== undefined ? "每月 " + data.reset_day + " 日" :
                (data.reset !== undefined ? data.reset : null)))));

  var usedStr = formatTrafficBytes(rawUsed, unit);
  var totalStr = formatTrafficBytes(rawTotal, unit);
  var restStr = formatTrafficBytes(rawRest, unit);

  var percentStr = "";
  if (data.percent !== undefined) {
    percentStr = String(data.percent);
    if (percentStr.indexOf("%") === -1) percentStr += "%";
  } else if (rawUsed !== null && rawTotal !== null) {
    var uNum = parseFloat(String(rawUsed));
    var tNum = parseFloat(String(rawTotal));
    if (!isNaN(uNum) && !isNaN(tNum) && tNum > 0) {
      percentStr = ((uNum / tNum) * 100).toFixed(1) + "%";
    }
  }

  var line = "";
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
    var resetStr = String(rawReset).replace(/^\d{4}-/, "").replace(/\s.*$/, "");
    if (resetStr) {
      if (line) line += " · " + resetStr + " 重置";
      else line = "重置: " + resetStr;
    }
  }

  return { line: line, used: usedStr, total: totalStr, rest: restStr, reset: rawReset };
}

function queryTraffic(baseToken, index, multi) {
  var kvKey = STORE_PREFIX + "traffic_" + index;
  var kvTsKey = STORE_PREFIX + "traffic_ts_" + index;

  var cached = storeRead(kvKey) || "";
  var cachedTs = parseInt(storeRead(kvTsKey) || "0", 10);
  var now = Date.now();
  var CACHE_TTL = 5 * 60 * 1000; // 缓存 5 分钟

  // 命中非强制刷新缓存
  if (!isManualTap && cached && now - cachedTs < CACHE_TTL) {
    return Promise.resolve(cached);
  }

  // 流量查询接口必须使用纯净 baseToken（不含 @0~4 后缀）
  var url = TRAFFIC_API_BASE + encodeURIComponent(baseToken);
  var opts = {
    url: url,
    headers: {
      "User-Agent":
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
      Accept: "application/json, text/plain, */*",
    },
  };
  if (REQUEST_TIMEOUT !== null) opts.timeout = REQUEST_TIMEOUT;

  return httpRequest("GET", opts)
    .then(function (r) {
      if (r.error) return cached;
      var data = null;
      try {
        var j = JSON.parse(r.body);
        if (j && (j.status === 200 || j.code === 200) && j.data) {
          data = j.data;
        }
      } catch (e) {}

      if (!data) return cached;
      var parsed = parseTrafficData(data);
      if (parsed && parsed.line) {
        var prefix = multi ? "📊 #" + (index + 1) + " " : "📊 ";
        var line = prefix + parsed.line;
        storeWrite(line, kvKey);
        storeWrite(String(now), kvTsKey);
        return line;
      }
      return cached;
    })
    .catch(function () {
      return cached;
    });
}

function fetchAllTraffic(tokenItems) {
  return Promise.all(
    tokenItems.map(function (item, i) {
      return queryTraffic(item.baseToken, i, tokenItems.length > 1);
    })
  );
}

/* ---------- 业务加白逻辑 ---------- */

function apiCall(actualToken, uaMode) {
  var url = API_BASE + encodeURIComponent(actualToken);
  var userAgent =
    uaMode && uaMode.toLowerCase() === "pc"
      ? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
      : "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";

  var opts = {
    url: url,
    headers: {
      "User-Agent": userAgent,
      Accept: "application/json, text/plain, */*",
    },
  };
  if (REQUEST_TIMEOUT !== null) opts.timeout = REQUEST_TIMEOUT;

  return httpRequest("GET", opts).then(function (r) {
    if (r.error) return { applied: false, error: r.error };
    var data = null;
    try {
      data = JSON.parse(r.body);
    } catch (e) {}

    if (!data) {
      return { applied: false, error: "响应非 JSON: " + String(r.body).slice(0, 80) };
    }

    if (data.status === 200) {
      return {
        applied: true,
        msg: data.msg || "加白成功",
        data: data.data,
      };
    } else {
      return {
        applied: false,
        error: data.msg || ("加白失败 (状态码 " + data.status + ")"),
        data: data.data,
      };
    }
  });
}

function ensureWhitelisted(item, index, uaMode) {
  var kvState = STORE_PREFIX + index;
  var ctx = { kvState: kvState, item: item };

  return apiCall(item.actualToken, uaMode).then(function (st) {
    ctx.st = st;
    return ctx;
  });
}

function describe(index, ctx) {
  var st = ctx.st;
  var item = ctx.item;
  var short = item.baseToken.length > 12 ? item.baseToken.slice(0, 10) + "…" : item.baseToken;
  var head = "#" + (index + 1) + " [" + short + (item.slotLabel ? " " + item.slotLabel : "") + "] ";
  if (st.applied) {
    return head + "✅ " + (st.msg || "加白成功");
  } else {
    return head + "❌ " + (st.error || "加白失败");
  }
}

/* ---------- 流程执行 ---------- */

var argConfig = parseArgument();

// 1. 判断是否手动点击面板刷新
var isManualTap = false;
try {
  if (typeof $trigger !== "undefined" && $trigger === "button") {
    isManualTap = true;
  }
} catch (e) {}
if (argConfig.force === "1" || argConfig.force === "true") {
  isManualTap = true;
}

// 2. 家庭 Wi-Fi 防占坑优化：若已在家庭 Wi-Fi 且非手动点击刷新，跳过上报保留配额
var currentSSID = getWifiSSID();
if (!isManualTap && currentSSID && argConfig.skip_wifi) {
  var skipList = argConfig.skip_wifi.split(/[,|;、\s]+/).map(function (s) {
    return s.trim().toLowerCase();
  });
  if (skipList.indexOf(currentSSID.toLowerCase()) !== -1) {
    var skipTitle = "GGY 加白 · 🌐 Wi-Fi: " + currentSSID;
    var skipContent = "已处于家庭 Wi-Fi，软路由固定槽位已覆盖，跳过上报保留配额";
    finish(skipTitle, skipContent, true);
    // 直接退出，不继续执行 runMain
  } else {
    runMain();
  }
} else {
  runMain();
}

function runMain() {
  // 解析配置的 tokens 列表（支持逗号、竖线、分号、换行分隔）
  var rawTokens =
    argConfig.tokens ||
    storeRead(TOKENS_KEY) ||
    storeRead(TOKENS_KEY_LEGACY) ||
    INLINE_TOKENS ||
    "";

  var tokens = rawTokens
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

  if (tokens.length === 0) {
    notify(
      "GGY 防火墙加白",
      "未配置 token",
      "请在模块参数 tokens 填入咕咕云白名单 token 或完整分享链接"
    );
    finish("GGY 加白：未配置 token", "请在模块参数填入 token 或链接，多个用逗号分割", false);
    return;
  }

  // 探测公网出口 IP
  detectPublicIp()
    .then(function (currentIp) {
      var lastIp = storeRead(STORE_PREFIX + "last_ip") || "";
      var lastTs = parseInt(storeRead(STORE_PREFIX + "last_ts") || "0", 10);
      var lastOk = storeRead(STORE_PREFIX + "last_ok") === "1";
      var maxAgeMs = (parseInt(argConfig.interval, 10) || 10) * 60 * 1000;
      var now = Date.now();
      var isMobileUa = (argConfig.ua || "mobile").toLowerCase() !== "pc";

      var ipDrift =
        lastIp &&
        currentIp &&
        (isMobileUa ? !sameC24(currentIp, lastIp) : currentIp !== lastIp);

      // 将 rawToken 解析为槽位管理对象（根据是否漂移决定是否轮换至下一槽位）
      var tokenItems = tokens.map(function (t, i) {
        return resolveActualToken(t, i, argConfig.slot, ipDrift);
      });

      var canSkip = false;
      var skipSubnet = "";

      // 智能探活节流：在同一 /24 网段内且心跳未超时，跳过向咕咕云重复调用加白
      if (!isManualTap && lastOk && currentIp && lastIp && now - lastTs < maxAgeMs) {
        if (isMobileUa) {
          if (sameC24(currentIp, lastIp)) {
            canSkip = true;
            skipSubnet = getCSubnet(currentIp);
          }
        } else {
          if (currentIp === lastIp) {
            canSkip = true;
            skipSubnet = currentIp + "/32";
          }
        }
      }

      if (canSkip) {
        return fetchAllTraffic(tokenItems).then(function (trafficLines) {
          var minsAgo = Math.max(0, Math.floor((now - lastTs) / 60000));
          var title = "GGY 加白 · 放行中" + (onCellular() ? " 📶 移动网络" : " 🌐 Wi-Fi");
          var content = "出口 IP: " + currentIp + "\n放行网段: " + skipSubnet + " (无需重报)";

          // 槽位状态提示
          var slotHints = tokenItems.map(function (it, idx) {
            if (it.slotMode === "rotate") return (tokenItems.length > 1 ? "#" + (idx + 1) + " " : "") + "槽位: 轮换 @" + it.activeSlot + " (共 " + it.rotateSlots.length + " 槽)";
            if (it.slotMode === "fixed") return (tokenItems.length > 1 ? "#" + (idx + 1) + " " : "") + "槽位: 固定 @" + it.activeSlot;
            return "";
          }).filter(function (s) { return !!s; });
          if (slotHints.length > 0) {
            content += "\n" + slotHints.join("\n");
          }

          var validTraffic = trafficLines.filter(function (s) { return !!s; });
          if (validTraffic.length > 0) {
            content += "\n" + validTraffic.join("\n");
          }

          content += "\n心跳保活: 持续有效 (" + (minsAgo === 0 ? "刚刚" : minsAgo + " 分钟前") + ")";
          finish(title, content, true);
        });
      }

      // 越界自愈或保活上报：并行调用咕咕云加白 API 与流量查询
      return Promise.all([
        Promise.all(
          tokenItems.map(function (it, i) {
            return ensureWhitelisted(it, i, argConfig.ua);
          })
        ),
        fetchAllTraffic(tokenItems),
      ]).then(function (res) {
        var results = res[0];
        var trafficLines = res[1];

        var okCount = 0;
        var lines = [];
        var changed = false;

        for (var i = 0; i < results.length; i++) {
          var st = results[i].st;
          if (st.applied) okCount++;
          lines.push(describe(i, results[i]));

          var state = (st.applied ? "1" : "0") + "|" + (st.msg || st.error || "");
          if (storeRead(results[i].kvState) !== state) {
            storeWrite(state, results[i].kvState);
            changed = true;
          }
        }

        var allOk = okCount === results.length;
        if (allOk) {
          if (currentIp) storeWrite(currentIp, STORE_PREFIX + "last_ip");
          storeWrite(String(now), STORE_PREFIX + "last_ts");
          storeWrite("1", STORE_PREFIX + "last_ok");

          tokenItems.forEach(function (it) {
            if (it.slotMode === "rotate" && it.activeSlot !== null) {
              storeWrite(String(it.activeSlot), it.slotKey);
            }
          });
        } else {
          storeWrite("0", STORE_PREFIX + "last_ok");
        }

        var title =
          "GGY 加白 " + okCount + "/" + results.length + (onCellular() ? " 📶 移动网络" : " 🌐 Wi-Fi");
        var content = lines.join("\n");

        var validTraffic = trafficLines.filter(function (s) { return !!s; });
        if (validTraffic.length > 0) {
          content += "\n" + validTraffic.join("\n");
        }

        if (currentIp) {
          content +=
            "\n出口 IP: " +
            currentIp +
            (isMobileUa ? " (" + getCSubnet(currentIp) + ")" : " (/32)");
        }

        // 仅在首次、状态变化、网段漂移自愈、出现失败或手动点击时弹出系统通知
        if (changed || ipDrift || !allOk || isManualTap) {
          var notifyTitle = ipDrift ? "GGY 加白 · 网段自愈" : "GGY 防火墙加白";
          notify(notifyTitle, title, content);
        }
        finish(title, content, allOk);
      });
    })
    .catch(function (e) {
      notify("GGY 防火墙加白", "脚本异常", String(e && e.message ? e.message : e));
      finish("GGY 加白：脚本异常", String(e && e.message ? e.message : e), false);
    });
}
