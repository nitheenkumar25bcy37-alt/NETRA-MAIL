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
    document.getElementById("apiOrigin").value = stored.netraApiOrigin || "http://127.0.0.1:8000";
});
chrome.storage.local.get("netraDashboardOrigin").then(stored => {
    document.getElementById("dashboardOrigin").value = stored.netraDashboardOrigin || "http://127.0.0.1:8501";
});

document.getElementById("saveApiKey").addEventListener("click", async () => {
    const input = document.getElementById("apiKey");
    try {
        const origin = netraOrigin(document.getElementById("apiOrigin").value.trim());
        const dashboardOrigin = netraOrigin(document.getElementById("dashboardOrigin").value.trim());
        if (origin.startsWith("https:") && !await chrome.permissions.request({origins: [origin + "/*"]})) {
            throw new Error("Server access was not granted.");
        }
        await chrome.storage.session.set({netraApiKey: input.value.trim(), netraApiKeyOrigin: origin});
        await chrome.storage.local.set({netraApiOrigin: origin});
        await chrome.storage.local.set({netraDashboardOrigin: dashboardOrigin});
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
            result.netraProtectionEnabled === true
        );
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
        const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
        const response = await chrome.tabs.sendMessage(tab.id, {type: "NETRA_ANALYZE_CURRENT_EMAIL"});
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

