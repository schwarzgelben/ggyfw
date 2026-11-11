/*
 * po0fw 调试脚本：每次运行必弹通知，回显运行环境与 $argument 原文。
 * 用于确认客户端（尤其 Shadowrocket）的 cron / network-changed 是否真的在跑、
 * argument 是否被传入。定位完问题请删除本模块。
 */
var envs = [];
if (typeof $task !== "undefined") envs.push("QX");
if (typeof $httpClient !== "undefined") envs.push("SurgeLike");
if (typeof $network !== "undefined") envs.push("$network");
if (typeof $persistentStore !== "undefined") envs.push("store");

var argText;
try {
  argText =
    typeof $argument === "undefined"
      ? "(undefined)"
      : typeof $argument === "object"
        ? JSON.stringify($argument)
        : String($argument);
} catch (e) {
  argText = "(error: " + e + ")";
}

var iface = "";
try {
  iface =
    ($network && $network.v4 && $network.v4.primaryInterface) || "(no v4)";
} catch (e) {
  iface = "(err)";
}

var title = "po0fw 调试 · 脚本已运行";
var body =
  "time: " + new Date().toTimeString().slice(0, 8) +
  "\nenv: " + (envs.join(",") || "unknown") +
  "\niface: " + iface +
  "\n$argument: " + argText.slice(0, 120);

if (typeof $notify !== "undefined") $notify(title, "", body);
else if (typeof $notification !== "undefined") $notification.post(title, "", body);

// 再测一次真实出网（走模块里的 DIRECT 规则）
if (typeof $httpClient !== "undefined") {
  $httpClient.get(
    { url: "https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=ping_test", timeout: 10 },
    function (error, response, data) {
      var line = error
        ? "HTTP ❌ " + String(error)
        : "HTTP ✅ status " + (response && (response.status || response.statusCode));
      if (typeof $notification !== "undefined")
        $notification.post("GGY 调试 · 出网测试", "", line);
      $done({});
    }
  );
} else {
  if (typeof $done !== "undefined") $done({});
}
