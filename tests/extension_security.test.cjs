const {test} = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");

test("extension sends session credentials with bounded, non-redirecting requests", async () => {
    let request;
    const context = vm.createContext({
        chrome: {
            storage: {local: {get: async () => ({})}, session: {get: async () => ({netraApiKey: "session-token", netraApiKeyOrigin: "http://127.0.0.1:8000"})}},
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
    assert.equal(request.options.headers["X-NETRA-API-Key"], "session-token");
    assert.equal(request.options.redirect, "error");
    assert.equal(request.options.credentials, "omit");
    assert.ok(request.options.signal);
    assert.equal(result.dashboard_url, "http://127.0.0.1:8501/?email_id=123e4567-e89b-42d3-a456-426614174000");
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
        storage: {session: {get: async () => ({netraApiKey: "secret", netraApiKeyOrigin: "https://old.example"})}},
        runtime: {onMessage: {addListener: () => {}}}
    }});
    for (const name of ["connection.js", "background.js"]) vm.runInContext(fs.readFileSync(path.join(__dirname, "../extension/" + name), "utf8"), context);
    const headers = await vm.runInContext('authenticatedHeaders("https://new.example")', context);
    assert.equal(headers["X-NETRA-API-Key"], undefined);
});
