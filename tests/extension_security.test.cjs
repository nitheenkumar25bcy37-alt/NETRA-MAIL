const {test} = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

test("manifest pins the same extension ID on every computer", () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "../extension/manifest.json"), "utf8"));
    const digest = crypto.createHash("sha256").update(Buffer.from(manifest.key, "base64")).digest().subarray(0, 16);
    const extensionId = [...digest].flatMap(byte => [byte >> 4, byte & 15]).map(value => String.fromCharCode(97 + value)).join("");
    assert.equal(extensionId, "knckclcnbppcnhinmehnpajloflmjcgm");
});

test("extension uses persistent local credentials with bounded, non-redirecting requests", async () => {
    let request;
    const context = vm.createContext({
        chrome: {
            storage: {local: {get: async () => ({netraApiKey: "saved-token", netraApiKeyOrigin: "https://netra-mail.onrender.com"})}},
            runtime: {id: "test-extension", onMessage: {addListener: () => {}}}
        },
        fetch: async (url, options) => {
            request = {url, options};
            return {ok: true, json: async () => ({risk_score: 12, email_id: "123e4567-e89b-42d3-a456-426614174000"})};
        },
        AbortSignal, console, URL, importScripts: () => {}
    });
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../extension/connection.js"), "utf8"), context);
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../extension/background.js"), "utf8"), context);
    const result = await vm.runInContext('analyzeEmail({subject: "Test", body: "Meeting tomorrow"})', context);
    assert.equal(request.options.headers["X-NETRA-API-Key"], "saved-token");
    assert.equal(request.options.redirect, "error");
    assert.equal(request.options.credentials, "omit");
    assert.ok(request.options.signal);
    assert.equal(
        result.dashboard_url,
        "https://netra-mail-dashboard.onrender.com/?email_id=123e4567-e89b-42d3-a456-426614174000&api_origin=https%3A%2F%2Fnetra-mail.onrender.com"
    );
});

test("extension installation configures hosted services and enables protection", async () => {
    let installed;
    let updates;
    const context = vm.createContext({
        URL, console, importScripts: () => {},
        chrome: {
            storage: {local: {
                get: async () => ({
                    netraApiOrigin: "http://127.0.0.1:8000",
                    netraDashboardOrigin: "http://127.0.0.1:8501"
                }),
                set: async values => { updates = values; }
            }},
            runtime: {
                onInstalled: {addListener: listener => { installed = listener; }},
                onMessage: {addListener: () => {}}
            }
        }
    });
    for (const name of ["connection.js", "background.js"]) {
        vm.runInContext(fs.readFileSync(path.join(__dirname, "../extension/" + name), "utf8"), context);
    }
    await installed();
    assert.deepEqual({...updates}, {
        netraApiOrigin: "https://netra-mail.onrender.com",
        netraDashboardOrigin: "https://netra-mail-dashboard.onrender.com",
        netraProtectionEnabled: true
    });
});

test("v2 confidence and risk are normalized without classifying unknown as safe", () => {
    const context = vm.createContext({
        chrome: {
            storage: {local: {get: () => {}}, onChanged: {addListener: () => {}}},
            runtime: {onMessage: {addListener: () => {}}}
        }, console
    });
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../extension/content.js"), "utf8"), context);
    const result = vm.runInContext('normalizeResult({risk_score: 82, confidence: 0.9, classification: "Phishing"})', context);
    assert.equal(result.riskLevel, "CRITICAL");
    assert.equal(result.confidence, 90);
    const linked = vm.runInContext('normalizeResult({risk_score: 10, email_id: "123e4567-e89b-42d3-a456-426614174000", dashboard_url: "http://127.0.0.1:8501/?email_id=123"})', context);
    assert.equal(linked.emailId, "123e4567-e89b-42d3-a456-426614174000");
    assert.equal(linked.dashboardUrl, "http://127.0.0.1:8501/?email_id=123");
    assert.equal(vm.runInContext('normalizeResult({risk_score: "bad"})', context), null);
    assert.equal(vm.runInContext('normalizeResult({})', context), null);
    assert.equal(vm.runInContext('createEmailKey("s", "a", "x".repeat(500) + "safe") === createEmailKey("s", "a", "x".repeat(500) + "changed")', context), false);
    assert.equal(vm.runInContext('createEmailKey("s", "a", "same", "safe") === createEmailKey("s", "a", "same", "changed")', context), false);
});

test("hosted origins reject plaintext remote servers and URL credentials", () => {
    const context = vm.createContext({URL});
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../extension/connection.js"), "utf8"), context);
    for (const value of ["http://example.org", "https://u:p@example.org", "https://example.org/path", "https://example.org/?token=x", "javascript:alert(1)"]) {
        assert.throws(() => vm.runInContext('netraOrigin(' + JSON.stringify(value) + ')', context));
    }
    assert.equal(vm.runInContext('netraOrigin("https://example.org/")', context), "https://example.org");
});

test("changing server never forwards the previous server credential", async () => {
    const context = vm.createContext({URL, console, importScripts: () => {}, chrome: {
        storage: {local: {get: async () => ({netraApiKey: "secret", netraApiKeyOrigin: "https://old.example"})}},
        runtime: {onMessage: {addListener: () => {}}}
    }});
    for (const name of ["connection.js", "background.js"]) vm.runInContext(fs.readFileSync(path.join(__dirname, "../extension/" + name), "utf8"), context);
    const headers = await vm.runInContext('authenticatedHeaders("https://new.example")', context);
    assert.equal(headers["X-NETRA-API-Key"], undefined);
});


test("configured Gmail consent submits selected ID to original-message endpoint", async () => {
    let request;
    const context = vm.createContext({
        chrome: {
            storage: {local: {get: async () => ({})}},
            identity: {getAuthToken: async options => { assert.equal(options.interactive, true); return {token: "test-provider-token"}; }},
            runtime: {getManifest: () => ({oauth2: {client_id: "test-client"}}), onMessage: {addListener: () => {}}}
        },
        fetch: async (url, options) => { request = {url, options}; return {ok: true, json: async () => ({email_id: "123e4567-e89b-42d3-a456-426614174000"})}; },
        URL, console, AbortSignal, importScripts: () => {}
    });
    for (const name of ["connection.js", "background.js"]) vm.runInContext(fs.readFileSync(path.join(__dirname, "../extension/" + name), "utf8"), context);
    await vm.runInContext('analyzeEmail({gmail_message_id: "18f123456789abcd"})', context);
    assert.equal(request.url, "https://netra-mail.onrender.com/api/v2/mailbox/analyze");
    assert.deepEqual(JSON.parse(request.options.body), {provider: "gmail", message_id: "18f123456789abcd", access_token: "test-provider-token"});
    assert.equal(request.options.redirect, "error");
    await assert.rejects(vm.runInContext('analyzeEmail({gmail_message_id: "invalid"})', context), /ID unavailable/);
});
