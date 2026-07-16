/**
 * registry-provider.test.ts - behavior assertions for the AgentCore Registry
 * custom-resource handler (lambda/registry-provider/index.js).
 * ==========================================================================
 * Self-contained, zero-dependency test (no jest wired in this package): uses
 * Node's built-in `assert` + a stubbed AWS SDK control-plane client injected via a
 * `Module.prototype.require` override (the real @aws-sdk client pkg is intentionally
 * NOT bundled). Runnable with `npx ts-node test/registry-provider.test.ts`; exits
 * non-zero on the first failed assertion so it gates the build.
 *
 * Covers the round-8 fixes:
 *   - #2  Create/Update pass a >=33-char clientToken (idempotent framework retries).
 *   - #5  a Delete during rollback with the SDK UNBUNDLED is a successful no-op
 *         (loadControl is inside the Delete branch, not before the switch).
 *   - #6  an Update that CHANGES the registry Name forces a REPLACE (new
 *         PhysicalResourceId) instead of a silent no-op rename.
 */
import * as assert from "node:assert";
import { Module } from "module";

const CONTROL_CLIENT_PKG = "@aws-sdk/client-bedrock-agentcore-control";
const HANDLER_PATH = "../lambda/registry-provider/index.js";

// --- Stub the (unbundled) control-plane SDK client -------------------------- //
// Each *Command constructor just records the params it was given; the client's
// send() returns a canned registry response and appends the command to `sent`.
interface Sent { name: string; input: any }
function makeFakeSdk(sent: Sent[]) {
  function cmd(name: string) {
    return class {
      input: any;
      constructor(input: any) {
        this.input = input;
        (this as any).__cmd = name;
      }
    };
  }
  return {
    BedrockAgentCoreControlClient: class {
      async send(command: any) {
        sent.push({ name: command.__cmd, input: command.input });
        return { registryArn: "arn:aws:bedrock-agentcore:us-east-1:000000000000:registry/r", registryId: command.input.name || command.input.registryIdentifier || "r" };
      }
    },
    CreateRegistryCommand: cmd("CreateRegistryCommand"),
    UpdateRegistryCommand: cmd("UpdateRegistryCommand"),
    DeleteRegistryCommand: cmd("DeleteRegistryCommand"),
    GetRegistryCommand: cmd("GetRegistryCommand"),
  };
}

// Install/uninstall a require() override that returns our fake for the SDK pkg.
let _sent: Sent[] = [];
let _sdkAvailable = true;
const _origRequire = (Module.prototype as any).require;
(Module.prototype as any).require = function (id: string) {
  if (id === CONTROL_CLIENT_PKG) {
    if (!_sdkAvailable) {
      const err: any = new Error("Cannot find module (test: SDK unbundled)");
      err.code = "MODULE_NOT_FOUND";
      throw err;
    }
    return makeFakeSdk(_sent);
  }
  return _origRequire.apply(this, arguments as any);
};

// Fresh import of the handler AFTER the override is installed.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { handler } = require(HANDLER_PATH);

async function run() {
  // --- #2: Create passes a >=33-char clientToken --------------------------- //
  _sent = []; _sdkAvailable = true;
  let res = await handler({
    RequestType: "Create",
    RequestId: "abc-123",
    ResourceProperties: { Name: "sentinel-registry", AutoApproval: "true" },
  });
  assert.strictEqual(_sent.length, 1);
  assert.strictEqual(_sent[0].name, "CreateRegistryCommand");
  assert.ok("clientToken" in _sent[0].input, "Create must pass a clientToken");
  assert.ok(
    String(_sent[0].input.clientToken).length >= 33,
    `clientToken must be >=33 chars, got ${_sent[0].input.clientToken}`,
  );
  assert.strictEqual(res.PhysicalResourceId, "sentinel-registry");
  console.log("[registry-provider] #2 Create clientToken (>=33) assertion passed");

  // A short RequestId is padded to the 33-char floor.
  _sent = [];
  await handler({ RequestType: "Create", RequestId: "x",
    ResourceProperties: { Name: "r", AutoApproval: "false" } });
  assert.ok(String(_sent[0].input.clientToken).length >= 33, "short RequestId must pad");
  console.log("[registry-provider] #2 short-RequestId padding assertion passed");

  // --- #5: Delete during rollback with SDK unbundled is a no-op success ---- //
  _sent = []; _sdkAvailable = false;   // simulate the SDK not bundled
  res = await handler({
    RequestType: "Delete",
    RequestId: "del-1",
    PhysicalResourceId: "sentinel-registry",
    ResourceProperties: {},
  });
  assert.strictEqual(res.PhysicalResourceId, "sentinel-registry",
    "Delete with unbundled SDK must return a no-op success, not throw");
  assert.strictEqual(_sent.length, 0, "no SDK call should have been attempted");
  console.log("[registry-provider] #5 Delete rollback-safe (unbundled SDK) assertion passed");

  // With the SDK available, Delete really calls DeleteRegistry.
  _sent = []; _sdkAvailable = true;
  await handler({ RequestType: "Delete", RequestId: "del-2",
    PhysicalResourceId: "r", ResourceProperties: {} });
  assert.strictEqual(_sent[0].name, "DeleteRegistryCommand");
  console.log("[registry-provider] #5 Delete calls DeleteRegistry when SDK present");

  // --- #6: Update with a Name change forces a REPLACE ---------------------- //
  _sent = []; _sdkAvailable = true;
  res = await handler({
    RequestType: "Update",
    RequestId: "upd-1",
    PhysicalResourceId: "sentinel-registry",
    ResourceProperties: { Name: "acme-registry", AutoApproval: "true" },
    OldResourceProperties: { Name: "sentinel-registry", AutoApproval: "true" },
  });
  // A rename must Create the new registry (framework then deletes the old id) and
  // return a NEW PhysicalResourceId — never a silent in-place UpdateRegistry no-op.
  assert.strictEqual(_sent[0].name, "CreateRegistryCommand",
    "a Name change must Create (replace), not UpdateRegistry");
  assert.notStrictEqual(res.PhysicalResourceId, "sentinel-registry",
    "a Name change must return a NEW PhysicalResourceId to force replacement");
  console.log("[registry-provider] #6 Name-change forces replace assertion passed");

  // An Update with the SAME name does an in-place UpdateRegistry (with clientToken).
  _sent = [];
  res = await handler({
    RequestType: "Update",
    RequestId: "upd-2",
    PhysicalResourceId: "sentinel-registry",
    ResourceProperties: { Name: "sentinel-registry", AutoApproval: "false" },
    OldResourceProperties: { Name: "sentinel-registry", AutoApproval: "true" },
  });
  assert.strictEqual(_sent[0].name, "UpdateRegistryCommand");
  assert.ok(String(_sent[0].input.clientToken).length >= 33, "Update must pass clientToken");
  assert.strictEqual(res.PhysicalResourceId, "sentinel-registry",
    "a same-name Update keeps the PhysicalResourceId");
  console.log("[registry-provider] #6 same-name Update stays in place assertion passed");

  console.log("\nALL registry-provider handler assertions PASSED");
}

run()
  .catch((e) => { console.error(e); process.exit(1); })
  .finally(() => { (Module.prototype as any).require = _origRequire; });
