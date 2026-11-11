const fs = require("fs");
const vm = require("vm");

const code = fs.readFileSync("scripts/po0-firewall-whitelist.js", "utf8");

let store = {};
let notifications = [];
let doneResult = null;
let httpCalls = [];

function makeSandbox(arg, trigger, network) {
  store = {};
  notifications = [];
  doneResult = null;
  httpCalls = [];

  return {
    $argument: arg,
    $trigger: trigger,
    $network: network || { v4: { primaryInterface: "pdp_ip0" } },
    $persistentStore: {
      read: (k) => store[k] || null,
      write: (v, k) => { store[k] = v; return true; }
    },
    $notification: {
      post: (t, s, b) => notifications.push({ t, s, b })
    },
    $httpClient: {
      get: (opts, cb) => {
        httpCalls.push(opts.url);
        if (opts.url.includes("1.1.1.1")) {
          // Tricky Cloudflare trace output where h=1.1.1.1 appears before ip=
          cb(null, { status: 200 }, "fl=123f45\nh=1.1.1.1\nip=117.136.32.15\nts=1710123456\n");
        } else if (opts.url.includes("3322.net")) {
          cb(null, { status: 200 }, "117.136.32.15\n");
        } else if (opts.url.includes("ipip.net")) {
          cb(null, { status: 200 }, "当前 IP：117.136.32.15 来自于：中国 广东 广州 移动");
        } else if (opts.url.includes("guguyun.com")) {
          cb(null, { status: 200 }, JSON.stringify({ status: 200, msg: "添加成功", data: [] }));
        } else {
          cb("not found", null, null);
        }
      }
    },
    $done: (res) => { doneResult = res; },
    setTimeout: setTimeout,
    Date: Date,
    JSON: JSON,
    String: String,
    parseInt: parseInt,
    Math: Math,
    Promise: Promise,
    encodeURIComponent: encodeURIComponent,
    decodeURIComponent: decodeURIComponent,
    console: console
  };
}

async function runTest(name, sandboxFn, verifyFn) {
  const sb = sandboxFn();
  const ctx = vm.createContext(sb);
  vm.runInContext(code, ctx);
  await new Promise(r => setTimeout(r, 200));
  verifyFn(sb);
  console.log(`✅ [PASS] ${name}`);
}

async function main() {
  console.log("Starting Comprehensive Logic Checks...\n");

  // Test 1: Surge query string + First Run
  await runTest("Surge Argument + First Run", 
    () => makeSandbox("tokens=tok1&skip_wifi=HomeWiFi&ua=mobile"),
    (sb) => {
      if (!doneResult || !doneResult.title.includes("GGY 加白 1/1")) throw new Error("Title mismatch: " + JSON.stringify(doneResult));
      if (!httpCalls.some(u => u.includes("guguyun.com"))) throw new Error("GGY API was not called");
      if (store["ggy_fw_last_ip"] !== "117.136.32.15") throw new Error("Store last_ip mismatch: " + store["ggy_fw_last_ip"]);
      if (store["ggy_fw_last_ok"] !== "1") throw new Error("Store last_ok mismatch");
    }
  );

  // Test 2: Loon Array format argument: ["tok_loon", "HomeSSID", "mobile"]
  await runTest("Loon Array Object Argument",
    () => makeSandbox(["tok_loon", "HomeSSID", "mobile"]),
    (sb) => {
      if (!httpCalls.some(u => u.includes("token=tok_loon"))) throw new Error("Loon token not extracted");
      if (!doneResult) throw new Error("Done was not called");
    }
  );

  // Test 3: Loon Bracket String: "[tok_bracket, HomeSSID, mobile]"
  await runTest("Loon Bracket String Argument",
    () => makeSandbox("[tok_bracket, HomeSSID, mobile]"),
    (sb) => {
      if (!httpCalls.some(u => u.includes("token=tok_bracket"))) throw new Error("Loon bracket token not extracted");
    }
  );

  // Test 4: Cloudflare trace anti-poisoning (must NOT extract 1.1.1.1 from h=1.1.1.1)
  await runTest("Cloudflare Trace Anti-Poisoning Check",
    () => {
      const sb = makeSandbox("tokens=test_cf");
      sb.$httpClient.get = (opts, cb) => {
        httpCalls.push(opts.url);
        if (opts.url.includes("1.1.1.1")) {
          cb(null, { status: 200 }, "fl=123f45\nh=1.1.1.1\nip=117.136.55.66\nts=1710123456\n");
        } else if (opts.url.includes("guguyun.com")) {
          cb(null, { status: 200 }, JSON.stringify({ status: 200, msg: "添加成功", data: [] }));
        } else {
          cb("fail", null, null); // 3322 and others fail, fallback to 1.1.1.1
        }
      };
      return sb;
    },
    (sb) => {
      if (store["ggy_fw_last_ip"] !== "117.136.55.66") {
        throw new Error("Extracted wrong IP (likely 1.1.1.1): " + store["ggy_fw_last_ip"]);
      }
    }
  );

  // Test 5: Same C24 subnet throttling (IP 117.136.32.88 vs 117.136.32.15)
  await runTest("Same C24 Subnet Throttling",
    () => {
      const sb = makeSandbox("tokens=tok1");
      // Preload store as if last run was 2 mins ago
      store["ggy_fw_last_ip"] = "117.136.32.15";
      store["ggy_fw_last_ts"] = String(Date.now() - 2 * 60 * 1000);
      store["ggy_fw_last_ok"] = "1";
      sb.$httpClient.get = (opts, cb) => {
        httpCalls.push(opts.url);
        if (opts.url.includes("3322.net")) {
          cb(null, { status: 200 }, "117.136.32.88\n"); // same /24
        } else if (opts.url.includes("guguyun.com")) {
          cb(null, { status: 200 }, JSON.stringify({ status: 200, msg: "添加成功", data: [] }));
        }
      };
      return sb;
    },
    (sb) => {
      if (httpCalls.some(u => u.includes("guguyun.com"))) throw new Error("GGY API should NOT be called on same C24");
      if (!doneResult.title.includes("放行中")) throw new Error("Title should indicate active pass: " + doneResult.title);
      if (notifications.length > 0) throw new Error("Should not send push notification on throttled run");
    }
  );

  // Test 6: Cross C24 subnet rapid self-healing (IP 117.136.99.12 vs 117.136.32.15)
  await runTest("Cross C24 Subnet Rapid Self-Healing",
    () => {
      const sb = makeSandbox("tokens=tok1");
      store["ggy_fw_last_ip"] = "117.136.32.15";
      store["ggy_fw_last_ts"] = String(Date.now() - 2 * 60 * 1000);
      store["ggy_fw_last_ok"] = "1";
      sb.$httpClient.get = (opts, cb) => {
        httpCalls.push(opts.url);
        if (opts.url.includes("3322.net")) {
          cb(null, { status: 200 }, "117.136.99.12\n"); // new /24!
        } else if (opts.url.includes("guguyun.com")) {
          cb(null, { status: 200 }, JSON.stringify({ status: 200, msg: "添加成功", data: [] }));
        }
      };
      return sb;
    },
    (sb) => {
      if (!httpCalls.some(u => u.includes("guguyun.com"))) throw new Error("GGY API MUST be called on cross C24 drift");
      if (notifications.length === 0) throw new Error("Must send push notification on subnet drift");
      if (!notifications[0].t.includes("网段自愈")) throw new Error("Notification title mismatch: " + notifications[0].t);
      if (store["ggy_fw_last_ip"] !== "117.136.99.12") throw new Error("last_ip not updated");
    }
  );

  // Test 7: Skip Wi-Fi in background cron
  await runTest("Skip Wi-Fi in Background Cron",
    () => makeSandbox("tokens=tok1&skip_wifi=HomeWiFi", undefined, { wifi: { ssid: "HomeWiFi" } }),
    (sb) => {
      if (httpCalls.length > 0) throw new Error("Should make 0 HTTP calls on skip_wifi");
      if (!doneResult.content.includes("已处于家庭 Wi-Fi")) throw new Error("Content mismatch");
    }
  );

  // Test 8: Manual Tap in Home Wi-Fi ($trigger === 'button') -> MUST execute!
  await runTest("Manual Tap in Home Wi-Fi Executes",
    () => makeSandbox("tokens=tok1&skip_wifi=HomeWiFi", "button", { wifi: { ssid: "HomeWiFi" } }),
    (sb) => {
      if (!httpCalls.some(u => u.includes("guguyun.com"))) throw new Error("Manual button tap MUST execute even on home Wi-Fi");
      if (notifications.length === 0) throw new Error("Manual button tap should pop notification");
    }
  );

  console.log("\n🎉 ALL 8 TESTS & EDGE CASES PASSED WITH 100% SUCCESS!");
}

main().catch(err => {
  console.error("Test failed:", err);
  process.exit(1);
});
