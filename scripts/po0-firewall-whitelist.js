/*
 * GGY (咕咕云) 防火墙白名单自动加白
 * 兼容：Surge / Stash / Shadowrocket / Loon / Quantumult X
 *
 * 端点：GET https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=<token>
 * 行为：调用咕咕云魔方插件白名单分享链接，将当前请求来源 IP 自动加入防火墙安全组白名单。
 * 响应：{"status":200,"msg":"...","data":[]} / {"status":400,"msg":"白名单分享链接无效或已失效","data":[]}
 *
 * 智能探活与自愈机制（方案 1）：
 * 1. 识别手机 UA（ua=mobile，默认）：固定槽位链接放行整段 /24（256个IP）。
 * 2. 轻量公网 IP 嗅探：直连探测本机出口公网 IP（直连 3322.net / ip.sb / 1.1.1.1）。
 * 3. 同 C 段智能节流：若当前出口 IP 与上次加白 IP 处于同一 /24 网段且在保活期内，
 *    判定为安全组已放行，自动跳过咕咕云 API 请求（零频次消耗、零断流）。
 * 4. 越界秒级自愈：每 2 分钟高频 cron 探活，一旦检测到基站 IP 跳出 /24 网段，
 *    立即发起咕咕云加白请求，将新网段加入防火墙，实现无感自愈。
 * 5. 手动刷新：点击面板按钮立即强制重新加白并刷新状态。
 *
 * 分流注意：
 * 加白请求与 IP 嗅探必须直连！必须配置分流规则：
 * DOMAIN,www.guguyun.com,DIRECT
 * DOMAIN-SUFFIX,3322.net,DIRECT
 * DOMAIN-SUFFIX,ip.sb,DIRECT
 * DOMAIN,1.1.1.1,DIRECT
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
  var m = s.match(/[?&]token=([^&#\s]+)/);
  if (m && m[1]) return decodeURIComponent(m[1]);
  if (/^https?:\/\//i.test(s)) return "";
  return s;
}

function parseArgument() {
  var res = { tokens: "", skip_wifi: "", ua: "mobile", interval: "10", force: "0" };
  if (typeof $argument === "undefined" || $argument === null) return res;
  if (typeof $argument === "object") {
    if ($argument.tokens !== undefined) res.tokens = String($argument.tokens);
    if ($argument.skip_wifi !== undefined) res.skip_wifi = String($argument.skip_wifi);
    if ($argument.ua !== undefined) res.ua = String($argument.ua);
    if ($argument.interval !== undefined) res.interval = String($argument.interval);
    if ($argument.force !== undefined) res.force = String($argument.force);
    return res;
  }
  var raw = String($argument).trim();
  if (/^["'].*["']$/.test(raw)) raw = raw.slice(1, -1);
  if (raw.charAt(0) === "{") {
    try {
      var p = JSON.parse(raw);
      if (p) {
        if (p.tokens !== undefined) res.tokens = String(p.tokens);
        if (p.skip_wifi !== undefined) res.skip_wifi = String(p.skip_wifi);
        if (p.ua !== undefined) res.ua = String(p.ua);
        if (p.interval !== undefined) res.interval = String(p.interval);
        if (p.force !== undefined) res.force = String(p.force);
        return res;
      }
    } catch (e) {}
  }
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
      }
    }
    if (foundKey) return res;
  }
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

function extractIPv4(text) {
  if (!text) return "";
  var m = String(text).match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/);
  return m ? m[0] : "";
}

function sameC24(ip1, ip2) {
  if (!ip1 || !ip2) return false;
  var seg1 = ip1.split(".");
  var seg2 = ip2.split(".");
  if (seg1.length !== 4 || seg2.length !== 4) return false;
  return seg1[0] === seg2[0] && seg1[1] === seg2[1] && seg1[2] === seg2[2];
}

function getCSubnet(ip) {
  if (!ip) return "";
  var seg = ip.split(".");
  if (seg.length !== 4) return ip;
  return seg[0] + "." + seg[1] + "." + seg[2] + ".0/24";
}

function detectPublicIp() {
  var probeUrls = [
    "http://ip.3322.net",
    "http://api-ipv4.ip.sb/ip",
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

/* ---------- 业务加白逻辑 ---------- */

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

// 2. 家庭 Wi-Fi 防占坑优化：若已在家庭 Wi-Fi，跳过上报以保留宝贵的动态轮换槽位
var currentSSID = getWifiSSID();
if (currentSSID && argConfig.skip_wifi) {
  var skipList = argConfig.skip_wifi.split(/[,|;、\s]+/).map(function (s) {
    return s.trim().toLowerCase();
  });
  if (skipList.indexOf(currentSSID.toLowerCase()) !== -1) {
    var skipTitle = "GGY 加白 · 🌐 Wi-Fi: " + currentSSID;
    var skipContent = "已处于家庭 Wi-Fi，软路由固定槽位已覆盖，跳过上报保留配额";
    finish(skipTitle, skipContent, true);
    // 直接退出
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

      var canSkip = false;
      var skipSubnet = "";

      // 智能探活节流：在同一 /24 网段内且心跳未超时，跳过向咕咕云重复调用
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
        var minsAgo = Math.max(0, Math.floor((now - lastTs) / 60000));
        var title = "GGY 加白 · 放行中" + (onCellular() ? " 📶 移动网络" : " 🌐 Wi-Fi");
        var content =
          "出口 IP: " + currentIp + "\n" +
          "放行网段: " + skipSubnet + " (无需重报)\n" +
          "心跳保活: 持续有效 (" + (minsAgo === 0 ? "刚刚" : minsAgo + " 分钟前") + ")";
        finish(title, content, true);
        return;
      }

      // 越界自愈或保活上报：调用咕咕云加白 API
      return Promise.all(
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
        if (allOk) {
          if (currentIp) storeWrite(currentIp, STORE_PREFIX + "last_ip");
          storeWrite(String(now), STORE_PREFIX + "last_ts");
          storeWrite("1", STORE_PREFIX + "last_ok");
        } else {
          storeWrite("0", STORE_PREFIX + "last_ok");
        }

        var ipDrift =
          lastIp &&
          currentIp &&
          (isMobileUa ? !sameC24(currentIp, lastIp) : currentIp !== lastIp);

        var title =
          "GGY 加白 " + okCount + "/" + results.length + (onCellular() ? " 📶 移动网络" : " 🌐 Wi-Fi");
        var content = lines.join("\n");
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
