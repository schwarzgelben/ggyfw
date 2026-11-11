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
        } else if (opts.url.includes("guguyun.com")) {
          cb(null, { status: 200 }, JSON.stringify({ status: 200, msg: "IP: 117.136.32.15 添加成功", data: [] }));
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
  console.log("Starting Test Suite for Restored Whitelist & Slot Logic...\n");

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
      if (!doneResult.content.includes("117.136.32.15")) throw new Error("Response IP missing in content: " + doneResult.content);
    }
  );

  // Test 2: Rotation Slot Mode (@rotate across 0..4)
  await runTest("Slot Rotation Mode (@rotate across 0..4)",
    () => makeSandbox("tokens=tok_rot@rotate&ua=mobile"),
    (sb) => {
      if (!httpCalls.some(u => u.includes("token=tok_rot%400") || u.includes("token=tok_rot@0"))) {
        throw new Error("Whitelist API should use slot @0 on initial run: " + JSON.stringify(httpCalls));
      }
      if (store["ggy_fw_slot_active_0"] !== "0") {
        throw new Error("Slot active should be 0, got: " + store["ggy_fw_slot_active_0"]);
      }
    }
  );

  // Test 3: Rotation Slot Pointer Persistence (Drift to next network uses slot 1)
  await runTest("Slot Rotation Advances on Network Change",
    () => {
      const sb = makeSandbox("tokens=tok_rot@rotate&ua=mobile");
      store["ggy_fw_slot_active_0"] = "0";
      store["ggy_fw_last_net"] = "wifi:CoffeeShop";
      // Current network is pdp_ip0 (cellular)
      return sb;
    },
    (sb) => {
      if (!httpCalls.some(u => u.includes("token=tok_rot%401") || u.includes("token=tok_rot@1"))) {
        throw new Error("Whitelist API should advance to slot @1 on network change: " + JSON.stringify(httpCalls));
      }
      if (store["ggy_fw_slot_active_0"] !== "1") {
        throw new Error("Slot active should be 1 after network change, got: " + store["ggy_fw_slot_active_0"]);
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

  // Test 6: Skip Wi-Fi in Background
  await runTest("Skip Wi-Fi in Background",
    () => makeSandbox("tokens=tok1&skip_wifi=HomeWiFi", undefined, { wifi: { ssid: "HomeWiFi" } }),
    (sb) => {
      if (httpCalls.length > 0) throw new Error("Should make 0 HTTP calls on skip_wifi");
      if (!doneResult.content.includes("已处于家庭 Wi-Fi")) throw new Error("Content mismatch: " + JSON.stringify(doneResult));
    }
  );

  // Test 7: Direct Whitelist Call does NOT probe 3322 / ip.sb / 1.1.1.1
  await runTest("No External IP Sniffing (No 3322 / ip.sb / 1.1.1.1)",
    () => makeSandbox("tokens=tok_clean"),
    (sb) => {
      const externalProbes = httpCalls.filter(u => u.includes("3322") || u.includes("ip.sb") || u.includes("1.1.1.1") || u.includes("ipip.net"));
      if (externalProbes.length > 0) {
        throw new Error("Found unwanted external IP sniffing calls: " + JSON.stringify(externalProbes));
      }
    }
  );

  console.log("\n🎉 ALL TESTS PASSED SUCCESSFULLY!");
}

main().catch(err => {
  console.error("Test failed:", err);
  process.exit(1);
});
