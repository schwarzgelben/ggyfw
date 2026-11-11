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
 *    网络切换或跨网漫游时自动轮流写入下一个槽位（0 -> 1 -> 2 -> 3 -> 4 -> 0），
 *    使得用户最近经过的 5 个基站/网络同时保持加白。
 * 3. 流量查询自动脱敏：查询流量时自动剥离 @0~@4 后缀，保证流量接口稳定命中。
 *
 * 分流注意：
 * 加白请求与流量查询必须直连！必须配置分流规则：
 * DOMAIN,www.guguyun.com,DIRECT
 *
 * token 来源（优先级从高到低）：
 * 1. argument: tokens=<token 或完整 URL>（Surge/Loon/Stash 模块参数，支持多 token 逗号或换行分割）
 * 2. 持久化存储 key "ggy_tokens" 或 "po0fw_tokens"（Quantumult X 等客户端可通过 BoxJs 写入）
 * 3. 下面的 INLINE_TOKENS 常量
 */

var INLINE_TOKENS = "";

var API_BASE = "https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=";
var TRAFFIC_API_BASE = "https://www.guguyun.com/cany_tencentecs/traffic/query?token=";
var STORE_PREFIX = "ggy_fw_";
var TOKENS_KEY = "ggy_tokens";
var TOKENS_KEY_LEGACY = "po0fw_tokens";
var TRAFFIC_TOKENS_KEY = "ggy_traffic_tokens";

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

function safeDecode(s) {
  if (!s) return "";
  try {
    return decodeURIComponent(s);
  } catch (e) {
    return s;
  }
}

function extractToken(raw) {
  if (!raw) return "";
  var s = String(raw).trim();
  if (s.indexOf("%") !== -1) s = safeDecode(s);
  var m = s.match(/(?:[?&]token=|^token=)([^&#\s]+)/i);
  if (m && m[1]) return safeDecode(m[1]).trim();
  if (/^https?:\/\//i.test(s)) return "";
  return s.trim();
}

function cleanTrafficToken(raw) {
  if (!raw) return "";
  var tok = extractToken(raw);
  tok = String(tok).replace(/(?:@|%40).*$/i, "").replace(/^token=/i, "").trim();
  return tok;
}

function parseArgument() {
  var res = {
    tokens: "",
    traffic_tokens: "",
    skip_wifi: "",
    ua: "mobile",
    interval: "10",
    force: "0",
    slot: "",
    from: "",
  };
  if (typeof $argument === "undefined" || $argument === null) return res;

  // 1. Loon 数组对象传参: [tokens, skip_wifi, ua, slot, interval, traffic_tokens]
  if (Array.isArray($argument)) {
    if ($argument[0] !== undefined) res.tokens = String($argument[0]);
    if ($argument[1] !== undefined) res.skip_wifi = String($argument[1]);
    if ($argument[2] !== undefined) res.ua = String($argument[2]);
    if ($argument[3] !== undefined) res.slot = String($argument[3]);
    if ($argument[4] !== undefined) res.interval = String($argument[4]);
    if ($argument[5] !== undefined) res.traffic_tokens = String($argument[5]);
    return res;
  }

  // 2. 普通 Object
  if (typeof $argument === "object") {
    if ($argument.tokens !== undefined) res.tokens = String($argument.tokens);
    if ($argument.traffic_tokens !== undefined) res.traffic_tokens = String($argument.traffic_tokens);
    if ($argument.traffic_token !== undefined) res.traffic_tokens = String($argument.traffic_token);
    if ($argument.skip_wifi !== undefined) res.skip_wifi = String($argument.skip_wifi);
    if ($argument.ua !== undefined) res.ua = String($argument.ua);
    if ($argument.interval !== undefined) res.interval = String($argument.interval);
    if ($argument.force !== undefined) res.force = String($argument.force);
    if ($argument.slot !== undefined) res.slot = String($argument.slot);
    if ($argument.from !== undefined) res.from = String($argument.from);
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
        if (p.traffic_tokens !== undefined) res.traffic_tokens = String(p.traffic_tokens);
        if (p.traffic_token !== undefined) res.traffic_tokens = String(p.traffic_token);
        if (p.skip_wifi !== undefined) res.skip_wifi = String(p.skip_wifi);
        if (p.ua !== undefined) res.ua = String(p.ua);
        if (p.interval !== undefined) res.interval = String(p.interval);
        if (p.force !== undefined) res.force = String(p.force);
        if (p.slot !== undefined) res.slot = String(p.slot);
        if (p.from !== undefined) res.from = String(p.from);
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
        if (arr[5] !== undefined) res.traffic_tokens = String(arr[5]);
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
      if (parts[5] !== undefined) res.traffic_tokens = parts[5].trim();
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
        var v = safeDecode(pairs[i].slice(eqIdx + 1).trim());
        if (k === "tokens") { res.tokens = v; foundKey = true; }
        else if (k === "traffic_tokens" || k === "traffic_token") { res.traffic_tokens = v; foundKey = true; }
        else if (k === "skip_wifi") { res.skip_wifi = v; foundKey = true; }
        else if (k === "ua") { res.ua = v || res.ua; foundKey = true; }
        else if (k === "interval") { res.interval = v || res.interval; foundKey = true; }
        else if (k === "force") { res.force = v; foundKey = true; }
        else if (k === "slot") { res.slot = v; foundKey = true; }
        else if (k === "from") { res.from = v; foundKey = true; }
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

function getCurrentNetworkKey() {
  var ssid = getWifiSSID();
  if (ssid) return "wifi:" + ssid;
  if (onCellular()) return "cellular";
  return "unknown";
}

function isValidIPv4(ip) {
  return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip);
}

function extractIPv4(text) {
  if (!text) return "";
  var s = String(text).trim();
  var m = s.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/);
  if (m && m[0]) {
    if (m[0] !== "127.0.0.1" && m[0] !== "0.0.0.0") return m[0];
  }
  return "";
}

function getCSubnet(ip) {
  if (!ip) return "";
  var seg = String(ip).trim().split(".");
  if (seg.length !== 4) return ip;
  return seg[0] + "." + seg[1] + "." + seg[2] + ".0/24";
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

/* ---------- 槽位解析与轮换管理 ---------- */

function parseSlotConfig(tokenStr, globalSlotArg) {
  var baseToken = tokenStr;
  var slotMode = ""; // "" (默认未指定) | "fixed" | "rotate"
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

function resolveActualToken(rawToken, index, globalSlotArg, shouldAdvanceRotate) {
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
      if (shouldAdvanceRotate) {
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

function formatGb(val) {
  if (val === null || val === undefined || isNaN(val)) return "";
  var num = parseFloat(val);
  if (isNaN(num)) return String(val);
  if (num >= 1024) return (num / 1024).toFixed(2) + " TB";
  if (num >= 1) {
    return (num % 1 === 0 ? num : (num >= 10 ? num.toFixed(1) : num.toFixed(2))) + " GB";
  }
  if (num > 0) return (num * 1024).toFixed(1) + " MB";
  return "0 GB";
}

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
      if (u === "KB" || u === "K") return (val >= 1048576 ? (val / 1048576).toFixed(2) + " GB" : (val / 1024).toFixed(1) + " MB");
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

  // 1. 优先适配咕咕云 v2 官方流量结构 (used_gb / total_gb / remaining_gb / used_transfer)
  if (data.used_gb !== undefined || data.total_gb !== undefined || data.used_transfer !== undefined) {
    var unit = (data.unit || "KB").toUpperCase();
    var factor = unit === "B" ? 1073741824 : (unit === "MB" ? 1024 : 1048576); // 默认 KB 转 GB

    var usedGb = data.used_gb !== undefined ? parseFloat(data.used_gb) :
                 (data.used_transfer !== undefined ? (parseFloat(data.used_transfer) / factor) : null);
    var totalGb = data.total_gb !== undefined ? parseFloat(data.total_gb) :
                  (data.total_transfer !== undefined ? (parseFloat(data.total_transfer) / factor) : null);
    var restGb = data.remaining_gb !== undefined ? parseFloat(data.remaining_gb) :
                 (data.remaining_transfer !== undefined ? (parseFloat(data.remaining_transfer) / factor) : null);

    var usedStr = usedGb !== null ? formatGb(usedGb) : "";
    var totalStr = data.unlimited ? "无限" : (totalGb !== null ? formatGb(totalGb) : "");
    var restStr = restGb !== null ? formatGb(restGb) : "";

    var pct = "";
    if (!data.unlimited && usedGb !== null && totalGb !== null && totalGb > 0) {
      pct = ((usedGb / totalGb) * 100).toFixed(1) + "%";
    }

    var line = "";
    if (usedStr && totalStr) {
      line = "流量: " + usedStr + " / " + totalStr + (pct ? " (" + pct + ")" : "");
    } else if (usedStr) {
      line = "已用: " + usedStr;
    }

    if (restStr && !data.unlimited) {
      line += (line ? " · 余 " : "剩余: ") + restStr;
    }

    var rawReset = data.reset_date || data.reset_time || data.traffic_reset || data.next_reset || null;
    if (rawReset) {
      var resetStr = String(rawReset).replace(/^\d{4}-/, "").replace(/\s.*$/, "");
      if (resetStr) line += " · " + resetStr + " 重置";
    }

    return { line: line, used: usedStr, total: totalStr, rest: restStr };
  }

  // 2. 兼容通用或其它旧版结构
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

function isTrafficError(text) {
  if (!text) return true;
  return (
    text.indexOf("失败") !== -1 ||
    text.indexOf("异常") !== -1 ||
    text.indexOf("不可用") !== -1 ||
    text.indexOf("超时") !== -1 ||
    text.indexOf("错误") !== -1 ||
    text.indexOf("未配置") !== -1
  );
}

function queryTraffic(baseToken, index, multi) {
  var kvKey = STORE_PREFIX + "traffic_" + index;
  var kvTsKey = STORE_PREFIX + "traffic_ts_" + index;

  var cached = storeRead(kvKey) || "";
  var cachedTs = parseInt(storeRead(kvTsKey) || "0", 10);
  var now = Date.now();
  var CACHE_TTL = 5 * 60 * 1000; // 缓存 5 分钟

  // 命中非强制刷新缓存且缓存不是错误信息
  if (!isManualTap && cached && now - cachedTs < CACHE_TTL && !isTrafficError(cached)) {
    return Promise.resolve(cached);
  }

  // 流量查询接口必须使用纯净 baseToken（不含 @0~4 或 %40 等后缀）
  var pureToken = cleanTrafficToken(baseToken);
  if (!pureToken) {
    return Promise.resolve(cached && !isTrafficError(cached) ? cached : "📊 流量: 未找到有效 Token");
  }

  var url = TRAFFIC_API_BASE + encodeURIComponent(pureToken);
  var opts = {
    url: url,
    headers: {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      Accept: "application/json, text/plain, */*",
      "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    },
  };
  if (REQUEST_TIMEOUT !== null) opts.timeout = REQUEST_TIMEOUT;

  function doFetch(attempt) {
    attempt = attempt || 1;
    return httpRequestOnce("GET", opts).then(function (r) {
      if (r.error || (r.status && r.status !== 200)) {
        if (attempt < 2) {
          return delay(1500).then(function () {
            return doFetch(attempt + 1);
          });
        }
      }
      return r;
    });
  }

  return doFetch(1)
    .then(function (r) {
      if (r.error) {
        if (cached && !isTrafficError(cached)) return cached;
        return "📊 流量: 查询超时/网络错误 (" + r.error + ")";
      }
      var data = null;
      var apiMsg = "";
      var j = null;
      try {
        j = JSON.parse(r.body);
        if (j) {
          apiMsg = j.msg || "";
          if ((j.status === 200 || j.code === 200) && j.data) {
            data = j.data;
          }
        }
      } catch (e) {
        if (cached && !isTrafficError(cached)) return cached;
        return "📊 流量: 响应解析失败 (" + String(r.body).slice(0, 30) + ")";
      }

      if (!data) {
        // 如果之前有成功的流量缓存，发生后端限频/暂不可用等瞬时异常时，保留上次有效展示
        if (cached && !isTrafficError(cached)) {
          return cached;
        }
        var msg = apiMsg || ("接口状态 " + (j ? j.status : "异常"));
        if (pureToken.toLowerCase().indexOf("ctecstr_") !== 0 && (msg.indexOf("暂不可用") !== -1 || msg.indexOf("请确认链接有效") !== -1)) {
          msg = "暂不可用 (需填入独立流量查询Token)";
        }
        return "📊 流量: " + msg;
      }

      var parsed = parseTrafficData(data);
      if (parsed && parsed.line) {
        var prefix = multi ? "📊 #" + (index + 1) + " " : "📊 ";
        var line = prefix + parsed.line;
        storeWrite(line, kvKey);
        storeWrite(String(now), kvTsKey);
        return line;
      }
      if (cached && !isTrafficError(cached)) return cached;
      return "📊 流量: 数据为空";
    })
    .catch(function (err) {
      if (cached && !isTrafficError(cached)) return cached;
      return "📊 流量: 请求异常 (" + describeHttpError(err) + ")";
    });
}

function fetchAllTraffic(tokenItems, trafficTokensArg) {
  var trafficTokens = [];
  if (trafficTokensArg) {
    trafficTokens = String(trafficTokensArg)
      .split(/[,|;、\r\n\s]+/)
      .map(cleanTrafficToken)
      .filter(function (s) { return s.length > 0; });
  }

  return Promise.all(
    tokenItems.map(function (item, i) {
      var tok = (trafficTokens[i] || (trafficTokens.length === 1 ? trafficTokens[0] : item.baseToken));
      return queryTraffic(tok, i, tokenItems.length > 1);
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

// 1. 判断是否手动点击刷新或面板触发
var isManualTap = false;
try {
  if (typeof $trigger !== "undefined" && $trigger === "button") {
    isManualTap = true;
  }
} catch (e) {}
if (argConfig.force === "1" || argConfig.force === "true") {
  isManualTap = true;
}

var scriptName = "";
try {
  if (typeof $script !== "undefined" && $script && $script.name) {
    scriptName = String($script.name).toLowerCase();
  }
} catch (e) {}

var isPanel =
  argConfig.from === "panel" ||
  isManualTap ||
  scriptName.indexOf("panel") !== -1 ||
  (typeof $panel !== "undefined");

// 2. 家庭 Wi-Fi 防占坑优化
var currentSSID = getWifiSSID();
var onHomeWifi = false;
if (currentSSID && argConfig.skip_wifi) {
  var skipList = argConfig.skip_wifi.split(/[,|;、\s]+/).map(function (s) {
    return s.trim().toLowerCase();
  });
  if (skipList.indexOf(currentSSID.toLowerCase()) !== -1) {
    onHomeWifi = true;
  }
}

// 若在家庭 Wi-Fi 且为纯后台任务（cron 或 network-changed 事件），静默退出不占配额也不打扰
if (onHomeWifi && !isPanel && !isManualTap && (argConfig.from === "cron" || argConfig.from === "event")) {
  finish("GGY 加白 · 🌐 Wi-Fi", "已处于家庭 Wi-Fi，跳过加白防占坑", true);
} else {
  runMain(onHomeWifi);
}

function runMain(skipWhitelist) {
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

  // 智能区分加白 Token 与独立流量 Token（若混填在 tokens 参数中，自动提取 ctecstr_ 流量 Token）
  var whitelistTokens = [];
  var inlineTrafficTokens = [];
  tokens.forEach(function (tok) {
    if (/^ctecstr_/i.test(tok)) {
      inlineTrafficTokens.push(tok);
    } else {
      whitelistTokens.push(tok);
    }
  });

  var effectiveTrafficTokens =
    argConfig.traffic_tokens ||
    (inlineTrafficTokens.length > 0 ? inlineTrafficTokens.join(",") : "") ||
    storeRead(TRAFFIC_TOKENS_KEY) ||
    "";
  var isOnlyTrafficTokens = whitelistTokens.length === 0 && inlineTrafficTokens.length > 0;
  if (whitelistTokens.length > 0 && inlineTrafficTokens.length > 0) {
    tokens = whitelistTokens;
  }

  if (tokens.length === 0) {
    notify(
      "GGY 防火墙加白",
      "未配置 token",
      "请在模块参数 tokens 填入咕咕云白名单 token 或完整分享链接"
    );
    finish("GGY 加白：未配置 token", "请在模块参数填入 token 或链接，多个用逗号分割", false);
    return;
  }

  var currentNet = getCurrentNetworkKey();
  var lastNet = storeRead(STORE_PREFIX + "last_net") || "";
  var netChanged = lastNet && currentNet !== lastNet;

  // 轮换槽位推进：当网络环境改变时，自动推进到下一个轮换槽位
  var tokenItems = tokens.map(function (t, i) {
    return resolveActualToken(t, i, argConfig.slot, netChanged);
  });

  // 如果处于家庭 Wi-Fi 下，跳过向咕咕云调用加白 API（保护槽位配额），但依然并行查询最新流量！
  var whitelistPromise;
  if (skipWhitelist) {
    whitelistPromise = Promise.resolve(
      tokenItems.map(function (it, i) {
        return {
          st: { applied: true, msg: "家庭 Wi-Fi (跳过加白防占坑)" },
          item: it,
          kvState: STORE_PREFIX + i,
        };
      })
    );
  } else if (isOnlyTrafficTokens) {
    whitelistPromise = Promise.resolve(
      tokenItems.map(function (it, i) {
        return {
          st: { applied: true, msg: "流量专属 Token" },
          item: it,
          kvState: STORE_PREFIX + i,
        };
      })
    );
  } else {
    whitelistPromise = Promise.all(
      tokenItems.map(function (it, i) {
        return ensureWhitelisted(it, i, argConfig.ua);
      })
    );
  }

  Promise.all([whitelistPromise, fetchAllTraffic(tokenItems, effectiveTrafficTokens)])
    .then(function (res) {
      var results = res[0];
      var trafficLines = res[1];

      var okCount = 0;
      var lines = [];
      var changed = false;
      var responseIp = "";

      for (var i = 0; i < results.length; i++) {
        var st = results[i].st;
        if (st.applied) okCount++;
        lines.push(describe(i, results[i]));

        var state = (st.applied ? "1" : "0") + "|" + (st.msg || st.error || "");
        if (storeRead(results[i].kvState) !== state) {
          storeWrite(state, results[i].kvState);
          changed = true;
        }

        // 若服务端返回了 IP，提取展示
        if (!responseIp) {
          var scanText = (st.msg || "") + " " + JSON.stringify(st.data || {});
          var foundIp = extractIPv4(scanText);
          if (foundIp) responseIp = foundIp;
        }
      }

      var allOk = okCount === results.length;
      var now = Date.now();

      if (allOk && !skipWhitelist) {
        storeWrite(currentNet, STORE_PREFIX + "last_net");
        storeWrite(String(now), STORE_PREFIX + "last_ts");
        storeWrite("1", STORE_PREFIX + "last_ok");
        if (responseIp) storeWrite(responseIp, STORE_PREFIX + "last_ip");

        tokenItems.forEach(function (it) {
          if (it.slotMode === "rotate" && it.activeSlot !== null) {
            storeWrite(String(it.activeSlot), it.slotKey);
          }
        });
      } else if (!skipWhitelist) {
        storeWrite("0", STORE_PREFIX + "last_ok");
      }

      var title;
      if (skipWhitelist) {
        title = "GGY 加白 · 🌐 Wi-Fi: " + (currentSSID || "家庭");
      } else if (isOnlyTrafficTokens) {
        title = "GGY 流量查询" + (onCellular() ? " 📶 移动网络" : " 🌐 Wi-Fi");
      } else {
        title = "GGY 加白 " + okCount + "/" + results.length + (onCellular() ? " 📶 移动网络" : " 🌐 Wi-Fi");
      }

      // 组装面板内容：流量第一优先级展示在首行！
      var contentParts = [];
      var validTraffic = trafficLines.filter(function (s) { return !!s; });
      if (validTraffic.length > 0) {
        contentParts.push(validTraffic.join("\n"));
      }
      if (lines.length > 0) {
        contentParts.push(lines.join("\n"));
      }
      if (responseIp) {
        var isMobileUa = (argConfig.ua || "mobile").toLowerCase() !== "pc";
        contentParts.push("出口 IP: " + responseIp + (isMobileUa ? " (" + getCSubnet(responseIp) + ")" : " (/32)"));
      }

      var content = contentParts.join("\n");

      // 状态变化、出现失败或手动点击时弹出系统通知（家庭 Wi-Fi 自动刷新不弹干扰通知）
      if (!skipWhitelist && (changed || !allOk || isManualTap)) {
        notify("GGY 防火墙加白", title, content);
      }
      finish(title, content, allOk);
    })
    .catch(function (e) {
      notify("GGY 防火墙加白", "脚本异常", String(e && e.message ? e.message : e));
      finish("GGY 加白：脚本异常", String(e && e.message ? e.message : e), false);
    });
}
