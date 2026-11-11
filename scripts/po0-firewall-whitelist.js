/*
 * GGY (咕咕云) 防火墙白名单自动加白
 * 兼容：Surge / Stash / Shadowrocket / Loon / Quantumult X
 *
 * 端点：GET https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=<token>
 * 行为：调用咕咕云魔方插件白名单分享链接，将当前请求来源 IP 自动加入防火墙安全组白名单。
 * 响应：{"status":200,"msg":"...","data":[]} / {"status":400,"msg":"白名单分享链接无效或已失效","data":[]}
 *
 * 分流注意：
 * 加白请求必须直连！必须配置分流规则：DOMAIN,www.guguyun.com,DIRECT
 * 否则请求经由代理节点发出，会把代理节点落地 IP 加白，导致本机失效。
 *
 * token 来源（优先级从高到低）：
 * 1. argument: tokens=<token 或完整 URL>（Surge/Loon/Stash 模块参数，支持多 token 逗号或换行分割）
 * 2. 持久化存储 key "po0fw_tokens" 或 "ggy_tokens"（Quantumult X 等客户端可通过 BoxJs 写入）
 * 3. 下面的 INLINE_TOKENS 常量
 */

var INLINE_TOKENS = "";

var API_BASE = "https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=";
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
    // 明确的业务错误（如 status 400 token失效）不重试
    if (j && j.status === 400) return false;
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
  // 兼容输入完整 URL 的情况：提取 ?token=xxx 或 &token=xxx
  var m = s.match(/[?&]token=([^&#\s]+)/);
  if (m && m[1]) return decodeURIComponent(m[1]);
  // 若传入的是 URL 但未提取出有效 token（如只传了前缀），返回空以避免误将 URL 当作 token
  if (/^https?:\/\//i.test(s)) return "";
  return s;
}

function parseArgument() {
  var res = { tokens: "", skip_wifi: "", ua: "mobile" };
  if (typeof $argument === "undefined" || $argument === null) return res;
  if (typeof $argument === "object") {
    if ($argument.tokens !== undefined) res.tokens = String($argument.tokens);
    if ($argument.skip_wifi !== undefined) res.skip_wifi = String($argument.skip_wifi);
    if ($argument.ua !== undefined) res.ua = String($argument.ua);
    return res;
  }
  var raw = String($argument).trim();
  if (/^["'].*["']$/.test(raw)) raw = raw.slice(1, -1);
  if (raw.charAt(0) === "{") {
    try {
      var p = JSON.parse(raw);
      if (p && p.tokens !== undefined) res.tokens = String(p.tokens);
      if (p && p.skip_wifi !== undefined) res.skip_wifi = String(p.skip_wifi);
      if (p && p.ua !== undefined) res.ua = String(p.ua);
      return res;
    } catch (e) {}
  }
  var mWifi = raw.match(/[&?]skip_wifi=([^&]+)/) || raw.match(/^skip_wifi=([^&]+)/);
  if (mWifi && mWifi[1]) res.skip_wifi = decodeURIComponent(mWifi[1]);

  var mUa = raw.match(/[&?]ua=([^&]+)/) || raw.match(/^ua=([^&]+)/);
  if (mUa && mUa[1]) res.ua = decodeURIComponent(mUa[1]);

  var mTok = raw.match(/tokens=(.*?)(?:&skip_wifi=|&ua=|$)/);
  if (mTok && mTok[1]) {
    res.tokens = decodeURIComponent(mTok[1]);
  } else if (raw.indexOf("tokens=") === 0) {
    res.tokens = raw.slice(7);
  } else if (!mWifi && !mUa) {
    res.tokens = raw;
  }
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

/* ---------- 业务逻辑 ---------- */

function apiCall(token, uaMode) {
  var url = API_BASE + encodeURIComponent(token);
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

function ensureWhitelisted(token, index, uaMode) {
  var kvState = STORE_PREFIX + index;
  var ctx = { kvState: kvState, token: token };

  return apiCall(token, uaMode).then(function (st) {
    ctx.st = st;
    return ctx;
  });
}

function describe(index, ctx) {
  var st = ctx.st;
  var short = ctx.token.length > 12 ? ctx.token.slice(0, 10) + "…" : ctx.token;
  var head = "#" + (index + 1) + " [" + short + "] ";
  if (st.applied) {
    return head + "✅ " + (st.msg || "加白成功");
  } else {
    return head + "❌ " + (st.error || "加白失败");
  }
}

// 解析参数与环境
var argConfig = parseArgument();

// 家庭 Wi-Fi 防占坑优化：若已在家庭 Wi-Fi，跳过上报以保留宝贵的动态轮换槽位
var currentSSID = getWifiSSID();
if (currentSSID && argConfig.skip_wifi) {
  var skipList = argConfig.skip_wifi.split(/[,|;、\s]+/).map(function (s) {
    return s.trim().toLowerCase();
  });
  if (skipList.indexOf(currentSSID.toLowerCase()) !== -1) {
    var skipTitle = "GGY 加白 · 🌐 Wi-Fi: " + currentSSID;
    var skipContent = "已处于家庭 Wi-Fi，软路由固定槽位已覆盖，跳过上报保留配额";
    finish(skipTitle, skipContent, true);
  }
}

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
} else {
  Promise.all(
    tokens.map(function (t, i) {
      return ensureWhitelisted(t, i, argConfig.ua);
    })
  ).then(function (results) {
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
    var title =
      "GGY 加白 " + okCount + "/" + results.length + (onCellular() ? " 📶 移动网络" : " 🌐 Wi-Fi");
    var content = lines.join("\n");

    // 状态变化或存在失败时弹出系统通知
    if (changed || !allOk) {
      notify("GGY 防火墙加白", title, content);
    }
    finish(title, content, allOk);
  }).catch(function (e) {
    notify("GGY 防火墙加白", "脚本异常", String(e && e.message ? e.message : e));
    finish("GGY 加白：脚本异常", String(e && e.message ? e.message : e), false);
  });
}

