importScripts("connection.js");

async function apiBaseURL() {
    const stored = await chrome.storage.local.get("netraApiOrigin");
    return netraOrigin(stored.netraApiOrigin || NETRA_DEFAULT_API_ORIGIN);
}

async function dashboardBaseURL() {
    const stored = await chrome.storage.local.get("netraDashboardOrigin");
    return netraOrigin(stored.netraDashboardOrigin || NETRA_DEFAULT_DASHBOARD_ORIGIN);
}

async function dashboardReportURL(emailId, apiOrigin) {
    const identifier = String(emailId || "");
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(identifier)) {
        return "";
    }
    const url = new URL(await dashboardBaseURL());
    url.searchParams.set("email_id", identifier);
    url.searchParams.set("api_origin", netraOrigin(apiOrigin));
    return url.toString();
}

// The submitter credential is stored only in this local extension profile. It
// is never synchronized or returned to content scripts.
async function authenticatedHeaders(origin) {
    const stored = await chrome.storage.local.get(["netraApiKey", "netraApiKeyOrigin"]);
    return {
        "Content-Type": "application/json",
        ...(stored.netraApiKey && stored.netraApiKeyOrigin === origin ? {"X-NETRA-API-Key": stored.netraApiKey} : {})
    };
}

// Fresh installations work without server-address or protection setup. This
// also migrates the retired Render hostname used during initial deployment.
if (chrome.runtime.onInstalled && chrome.runtime.onInstalled.addListener) {
    chrome.runtime.onInstalled.addListener(async () => {
        const stored = await chrome.storage.local.get([
            "netraApiOrigin",
            "netraDashboardOrigin",
            "netraProtectionEnabled"
        ]);
        const updates = {};
        if (!stored.netraApiOrigin ||
            ["http://127.0.0.1:8000", "http://localhost:8000", "https://netra-mail-api.onrender.com"].includes(stored.netraApiOrigin)) {
            updates.netraApiOrigin = NETRA_DEFAULT_API_ORIGIN;
        }
        if (!stored.netraDashboardOrigin ||
            ["http://127.0.0.1:8501", "http://localhost:8501"].includes(stored.netraDashboardOrigin)) {
            updates.netraDashboardOrigin = NETRA_DEFAULT_DASHBOARD_ORIGIN;
        }
        if (typeof stored.netraProtectionEnabled !== "boolean") {
            updates.netraProtectionEnabled = true;
        }
        if (Object.keys(updates).length) {
            await chrome.storage.local.set(updates);
        }
    });
}

async function checkIdentity() {
    const API_BASE_URL = await apiBaseURL();
    const response = await fetch(API_BASE_URL + "/api/v2/me", {
        headers: await authenticatedHeaders(API_BASE_URL), cache: "no-store",
        credentials: "omit", redirect: "error", signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) throw new Error("Backend authentication failed (HTTP " + response.status + ").");
    return response.json();
}


// ============================================================
// API HEALTH CHECK
// ============================================================

async function checkBackendHealth() {
    try {
        const API_BASE_URL = await apiBaseURL();
        const response = await fetch(
            `${API_BASE_URL}/health`,
            {
                method: "GET",
                cache: "no-store",
                signal: AbortSignal.timeout(10000),
                redirect: "error",
                credentials: "omit"
            }
        );

        if (!response.ok) {
            return {
                available: false,
                status: response.status
            };
        }

        const data = await response.json();

        return {
            available: data.status === "healthy",
            status: response.status,
            data
        };

    } catch (error) {

        console.error(
            "[NETRA Background] Health check failed:",
            error
        );

        return {
            available: false,
            error: error.message
        };
    }
}


// ============================================================
// V2 EMAIL ANALYSIS
// ============================================================

async function analyzeEmail(email) {
    const API_BASE_URL = await apiBaseURL();

    if (!email || typeof email !== "object") {
        throw new Error("Invalid email payload.");
    }

    const payload = {
        subject: String(email.subject || ""),
        sender: String(email.sender || ""),
        recipient: String(email.recipient || ""),
        reply_to: String(email.reply_to || ""),
        body: String(email.body || ""),
        html: String(email.html || ""),
        headers: String(email.headers || ""),
        received_headers: String(
            email.received_headers || ""
        )
    };


    if (
        !payload.subject &&
        !payload.sender &&
        !payload.body &&
        !payload.html
    ) {
        throw new Error(
            "No usable email content was extracted."
        );
    }


    const response = await fetch(
        `${API_BASE_URL}/api/v2/emails/analyze`,
        {
            method: "POST",

            headers: await authenticatedHeaders(API_BASE_URL),

            body: JSON.stringify(payload),

            cache: "no-store",
            signal: AbortSignal.timeout(45000),
            redirect: "error",
            credentials: "omit"
        }
    );


    let data = null;

    try {
        data = await response.json();
    } catch {
        data = null;
    }


    if (!response.ok) {

        const detail =
            data &&
            (
                data.detail ||
                data.message ||
                data.error
            );

        throw new Error(
            detail ||
            `NETRA backend returned HTTP ${response.status}.`
        );
    }


    if (!data) {
        throw new Error(
            "NETRA returned an empty response."
        );
    }


    data.dashboard_url = await dashboardReportURL(data.email_id, API_BASE_URL);
    return data;
}


// ============================================================
// MESSAGE ROUTER
// ============================================================

chrome.runtime.onMessage.addListener(
    (message, sender, sendResponse) => {

        if (sender.id !== chrome.runtime.id) {
            return false;
        }

        if (!message || !message.type) {
            return;
        }
        if (message.type === "NETRA_CONNECTION") {
            checkIdentity()
                .then(identity => sendResponse({success: true, identity}))
                .catch(error => sendResponse({success: false, error: error.message}));
            return true;
        }


        // ----------------------------------------------------
        // HEALTH
        // ----------------------------------------------------

        if (message.type === "NETRA_HEALTH") {

            checkBackendHealth()
                .then(result => {

                    sendResponse({
                        success: true,
                        ...result
                    });

                })
                .catch(error => {

                    sendResponse({
                        success: false,
                        error: error.message
                    });

                });

            return true;
        }


        // ----------------------------------------------------
        // ANALYZE EMAIL
        // ----------------------------------------------------

        if (message.type === "NETRA_ANALYZE_EMAIL") {

            analyzeEmail(message.email)
                .then(result => {

                    sendResponse({
                        success: true,
                        data: result
                    });

                })
                .catch(error => {

                    console.error(
                        "[NETRA Background] Analysis failed:",
                        error
                    );

                    sendResponse({
                        success: false,
                        error: error.message
                    });

                });

            return true;
        }


        // ----------------------------------------------------
        // UNKNOWN MESSAGE
        // ----------------------------------------------------

        sendResponse({
            success: false,
            error: "Unknown NETRA message type."
        });

        return false;
    }
);


// ============================================================
// STARTUP LOG
// ============================================================

console.log(
    "[NETRA Background] NETRA-Mail Shield service worker loaded."
);
