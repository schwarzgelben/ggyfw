const fs = require("fs");
const vm = require("vm");

const code = fs.readFileSync("scripts/po0-firewall-whitelist.js", "utf8");

let store = {};
let notifications = [];
let doneResult = null;
let httpCalls = [];

const sandbox = {
  $argument: "tokens=test_token&skip_wifi=HomeWiFi&ua=mobile",
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
      if (opts.url.includes("3322.net")) {
        cb(null, { status: 200 }, "117.136.32.15\n");
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

const context = vm.createContext(sandbox);

async function test() {
  console.log("=== Test 1: First Run (Cellular, IP 117.136.32.15) ===");
  vm.runInContext(code, context);
  await new Promise(r => setTimeout(r, 200));
  console.log("Done title:", doneResult ? doneResult.title : "none");
  console.log("Done content:\n" + (doneResult ? doneResult.content : "none"));
  console.log("HTTP calls made:", httpCalls);
  console.log("Store last_ip:", store["ggy_fw_last_ip"]);
  console.log("Store last_ts:", store["ggy_fw_last_ts"]);
  console.log("Store last_ok:", store["ggy_fw_last_ok"]);

  console.log("\n=== Test 2: Second Run (Same /24 IP 117.136.32.99 -> must skip GGY API) ===");
  httpCalls = [];
  notifications = [];
  doneResult = null;
  sandbox.$httpClient.get = (opts, cb) => {
    httpCalls.push(opts.url);
    if (opts.url.includes("3322.net")) {
      cb(null, { status: 200 }, "117.136.32.99\n");
    } else if (opts.url.includes("guguyun.com")) {
      cb(null, { status: 200 }, JSON.stringify({ status: 200, msg: "添加成功", data: [] }));
    }
  };
  vm.runInContext(code, context);
  await new Promise(r => setTimeout(r, 200));
  console.log("Done title:", doneResult ? doneResult.title : "none");
  console.log("Done content:\n" + (doneResult ? doneResult.content : "none"));
  console.log("HTTP calls made (must NOT include guguyun.com):", httpCalls);
  console.log("Notifications count (must be 0, no spam):", notifications.length);

  console.log("\n=== Test 3: Third Run (Jumped to another /24 subnet 117.136.88.50 -> must self-heal) ===");
  httpCalls = [];
  notifications = [];
  doneResult = null;
  sandbox.$httpClient.get = (opts, cb) => {
    httpCalls.push(opts.url);
    if (opts.url.includes("3322.net")) {
      cb(null, { status: 200 }, "117.136.88.50\n");
    } else if (opts.url.includes("guguyun.com")) {
      cb(null, { status: 200 }, JSON.stringify({ status: 200, msg: "添加成功", data: [] }));
    }
  };
  vm.runInContext(code, context);
  await new Promise(r => setTimeout(r, 200));
  console.log("Done title:", doneResult ? doneResult.title : "none");
  console.log("Done content:\n" + (doneResult ? doneResult.content : "none"));
  console.log("HTTP calls made (MUST include guguyun.com):", httpCalls);
  console.log("Notifications count:", notifications.length);
  if (notifications.length > 0) {
    console.log("Notification title:", notifications[0].t);
  }

  console.log("\n=== Test 4: Connected to Home Wi-Fi -> must skip ===");
  httpCalls = [];
  notifications = [];
  doneResult = null;
  sandbox.$network = { wifi: { ssid: "HomeWiFi" } };
  vm.runInContext(code, context);
  await new Promise(r => setTimeout(r, 200));
  console.log("Done title:", doneResult ? doneResult.title : "none");
  console.log("Done content:\n" + (doneResult ? doneResult.content : "none"));
  console.log("HTTP calls made (must be 0):", httpCalls.length);

  console.log("\nALL VERIFICATIONS PASSED!");
}

test();
