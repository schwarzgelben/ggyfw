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
        if (opts.url.includes("traffic/query")) {
          cb(null, { status: 200 }, JSON.stringify({
            status: 200,
            msg: "查询成功",
            data: {
              used: "15.3G",
              total: "1000G",
              rest: "984.7G",
              reset_time: "2026-12-01"
            }
          }));
        } else if (opts.url.includes("1.1.1.1")) {
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
  console.log("Starting Comprehensive Logic Checks with Slot Adaptation & Traffic Query...\n");

  // Test 1: Surge query string + First Run with Traffic Query & Fixed Slot @0
  await runTest("Fixed Slot @0 + Traffic Query", 
    () => makeSandbox("tokens=tok1@0&skip_wifi=HomeWiFi&ua=mobile"),
    (sb) => {
      if (!doneResult || !doneResult.title.includes("GGY 加白 1/1")) throw new Error("Title mismatch: " + JSON.stringify(doneResult));
      if (!httpCalls.some(u => u.includes("token=tok1%400") || u.includes("token=tok1@0"))) {
        throw new Error("Whitelist API was not called with token@0: " + JSON.stringify(httpCalls));
      }
      // Traffic query MUST use base token without @0
      if (!httpCalls.some(u => u.includes("traffic/query?token=tok1") && !u.includes("%400") && !u.includes("@0"))) {
        throw new Error("Traffic query did not strip @0 suffix: " + JSON.stringify(httpCalls));
      }
      if (!doneResult.content.includes("📊 流量: 15.3G / 1000G")) throw new Error("Traffic line missing: " + doneResult.content);
      if (!doneResult.content.includes("@0")) throw new Error("Slot @0 missing in describe: " + doneResult.content);
    }
  );

  // Test 2: Rotation Slot Mode (@rotate across 0..4)
  await runTest("Slot Rotation Mode (@rotate across 0..4)",
    () => makeSandbox("tokens=tok_rot@rotate&ua=mobile"),
    (sb) => {
      // First run should use slot 0
      if (!httpCalls.some(u => u.includes("token=tok_rot%400") || u.includes("token=tok_rot@0"))) {
        throw new Error("Whitelist API should use slot @0 on initial run: " + JSON.stringify(httpCalls));
      }
      if (store["ggy_fw_slot_active_0"] !== "0") {
        throw new Error("Slot active should be 0, got: " + store["ggy_fw_slot_active_0"]);
      }
    }
  );

  // Test 3: Rotation Slot Pointer Persistence (Drift to next subnet uses slot 1)
  await runTest("Slot Rotation Advances on Subnet Drift",
    () => {
      const sb = makeSandbox("tokens=tok_rot@rotate&ua=mobile");
      store["ggy_fw_slot_active_0"] = "0";
      store["ggy_fw_last_ip"] = "117.136.32.15";
      store["ggy_fw_last_ts"] = String(Date.now() - 2 * 60 * 1000);
      store["ggy_fw_last_ok"] = "1";
      sb.$httpClient.get = (opts, cb) => {
        httpCalls.push(opts.url);
        if (opts.url.includes("traffic/query")) {
          cb(null, { status: 200 }, JSON.stringify({ status: 200, msg: "ok", data: { used: "20G", total: "1000G" } }));
        } else if (opts.url.includes("3322.net")) {
          cb(null, { status: 200 }, "117.136.88.99\n"); // new subnet!
        } else if (opts.url.includes("guguyun.com")) {
          cb(null, { status: 200 }, JSON.stringify({ status: 200, msg: "添加成功", data: [] }));
        }
      };
      return sb;
    },
    (sb) => {
      if (!httpCalls.some(u => u.includes("token=tok_rot%401") || u.includes("token=tok_rot@1"))) {
        throw new Error("Whitelist API should use slot @1 on second drift: " + JSON.stringify(httpCalls));
      }
      if (store["ggy_fw_slot_active_0"] !== "1") {
        throw new Error("Slot active should be 1 after drift, got: " + store["ggy_fw_slot_active_0"]);
      }
    }
  );

  // Test 4: Global slot argument: tokens=tok1&slot=3
  await runTest("Global slot=3 Argument",
    () => makeSandbox("tokens=tok1&slot=3&ua=mobile"),
    (sb) => {
      if (!httpCalls.some(u => u.includes("token=tok1%403") || u.includes("token=tok1@3"))) {
        throw new Error("Whitelist API did not use global slot 3: " + JSON.stringify(httpCalls));
      }
    }
  );

  // Test 5: Loon Array format argument with slot
  await runTest("Loon Array Object Argument with slot",
    () => makeSandbox(["tok_loon", "HomeSSID", "mobile", "2"]),
    (sb) => {
      if (!httpCalls.some(u => u.includes("token=tok_loon%402") || u.includes("token=tok_loon@2"))) {
        throw new Error("Loon slot 2 not extracted");
      }
    }
  );

  // Test 6: Cloudflare trace anti-poisoning (must NOT extract 1.1.1.1 from h=1.1.1.1)
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
          cb("fail", null, null);
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

  // Test 7: Same C24 subnet throttling (IP 117.136.32.88 vs 117.136.32.15)
  await runTest("Same C24 Subnet Throttling",
    () => {
      const sb = makeSandbox("tokens=tok1@0");
      store["ggy_fw_last_ip"] = "117.136.32.15";
      store["ggy_fw_last_ts"] = String(Date.now() - 2 * 60 * 1000);
      store["ggy_fw_last_ok"] = "1";
      store["ggy_fw_traffic_0"] = "📊 流量: 15.3G / 1000G (1.5%) · 12-01 重置";
      store["ggy_fw_traffic_ts_0"] = String(Date.now() - 60 * 1000);
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
      if (httpCalls.some(u => u.includes("firewall/whitelist"))) throw new Error("GGY whitelist API should NOT be called on same C24");
      if (!doneResult.title.includes("放行中")) throw new Error("Title should indicate active pass: " + doneResult.title);
      if (!doneResult.content.includes("槽位: 固定 @0")) throw new Error("Slot info missing in panel: " + doneResult.content);
    }
  );

  // Test 8: Skip Wi-Fi in Background Cron
  await runTest("Skip Wi-Fi in Background Cron",
    () => makeSandbox("tokens=tok1&skip_wifi=HomeWiFi", undefined, { wifi: { ssid: "HomeWiFi" } }),
    (sb) => {
      if (httpCalls.length > 0) throw new Error("Should make 0 HTTP calls on skip_wifi");
      if (!doneResult.content.includes("已处于家庭 Wi-Fi")) throw new Error("Content mismatch");
    }
  );

  console.log("\n🎉 ALL TESTS WITH SLOT ADAPTATION & ROTATION PASSED WITH 100% SUCCESS!");
}

main().catch(err => {
  console.error("Test failed:", err);
  process.exit(1);
});
