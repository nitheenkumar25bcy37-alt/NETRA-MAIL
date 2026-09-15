// ============================================================
// NETRA-MAIL SHIELD POPUP
// ============================================================

const toggle =
    document.getElementById(
        "protectionToggle"
    );

const statusText =
    document.getElementById(
        "statusText"
    );

const statusDot =
    document.getElementById(
        "statusDot"
    );

const analyzeButton = document.getElementById("analyzeButton");
const result = document.getElementById("result");
chrome.storage.local.get("netraApiOrigin").then(stored => {
    document.getElementById("apiOrigin").value = stored.netraApiOrigin || NETRA_DEFAULT_API_ORIGIN;
});
chrome.storage.local.get("netraDashboardOrigin").then(stored => {
    document.getElementById("dashboardOrigin").value = stored.netraDashboardOrigin || NETRA_DEFAULT_DASHBOARD_ORIGIN;
});

document.getElementById("saveApiKey").addEventListener("click", async () => {
    const input = document.getElementById("apiKey");
    try {
        const origin = netraOrigin(document.getElementById("apiOrigin").value.trim());
        const dashboardOrigin = netraOrigin(document.getElementById("dashboardOrigin").value.trim());
        if (origin.startsWith("https:") && !await chrome.permissions.request({origins: [origin + "/*"]})) {
            throw new Error("Server access was not granted.");
        }
        await chrome.storage.local.set({
            netraApiKey: input.value.trim(),
            netraApiKeyOrigin: origin,
            netraApiOrigin: origin,
            netraDashboardOrigin: dashboardOrigin
        });
        input.value = "";
        const connection = await chrome.runtime.sendMessage({type: "NETRA_CONNECTION"});
        if (!connection || !connection.success) {
            result.textContent = "Key saved, but connection failed: " + (connection && connection.error || "Backend unavailable.");
        } else {
            result.textContent = "Connected as " + connection.identity.subject + " (" + connection.identity.role + ").";
        }
    } catch (error) {
        result.textContent = error.message || "Unable to store the backend key.";
    }
});


// ============================================================
// UPDATE PROTECTION UI
// ============================================================

function updateUI(enabled) {

    toggle.checked =
        enabled;


    if (enabled) {

        statusText.textContent =
            "ON";

        statusDot.classList.remove(
            "off"
        );

        statusDot.classList.add(
            "on"
        );

    }
    else {

        statusText.textContent =
            "OFF";

        statusDot.classList.remove(
            "on"
        );

        statusDot.classList.add(
            "off"
        );
    }
}


// ============================================================
// LOAD STATE
// ============================================================

chrome.storage.local.get(
    ["netraProtectionEnabled"],
    (result) => {

        updateUI(
            result.netraProtectionEnabled !== false
        );
        if (typeof result.netraProtectionEnabled !== "boolean") {
            chrome.storage.local.set({netraProtectionEnabled: true});
        }
    }
);


// ============================================================
// TOGGLE
// ============================================================

toggle.addEventListener(
    "change",
    () => {

        const enabled =
            toggle.checked;


        chrome.storage.local.set(
            {
                netraProtectionEnabled:
                    enabled
            },
            () => {

                updateUI(
                    enabled
                );
            }
        );
    }
);


analyzeButton.addEventListener("click", async () => {
    result.textContent = "Analyzing the currently open email…";
    analyzeButton.disabled = true;
    try {
        const settings = await chrome.storage.local.get("netraProtectionEnabled");
        if (settings.netraProtectionEnabled === false) {
            throw new Error("Turn on Email Protection, then select Analyze current email.");
        }
        const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
        if (!tab || !Number.isInteger(tab.id) || !tab.url ||
            new URL(tab.url).origin !== "https://mail.google.com") {
            throw new Error("Open an email in Gmail, then open NETRA and try again.");
        }
        let response;
        try {
            response = await chrome.tabs.sendMessage(tab.id, {type: "NETRA_ANALYZE_CURRENT_EMAIL"});
        } catch (error) {
            if (/receiving end does not exist|could not establish connection|message port closed|message channel closed|extension context invalidated/i.test(error.message || "")) {
                throw new Error("Gmail needs a refresh after the extension update. Refresh the Gmail tab, reopen NETRA, and analyze again.");
            }
            throw error;
        }
        if (!response || !response.success) {
            throw new Error((response && response.error) || "Open a Gmail email, enable protection, and try again.");
        }
        const finding = response.result || {};
        result.textContent = `Result: ${finding.riskLevel || "UNKNOWN"} · ${finding.score ?? 0}/100`;
        if (finding.dashboardUrl) {
            const link = document.createElement("a");
            link.href = finding.dashboardUrl;
            link.target = "_blank";
            link.rel = "noopener noreferrer";
            link.textContent = "View forensic report";
            link.style.display = "block";
            link.style.marginTop = "8px";
            result.appendChild(link);
        }
    } catch (error) {
        result.textContent = `Unable to analyze: ${error.message}`;
    } finally {
        analyzeButton.disabled = false;
    }
});

