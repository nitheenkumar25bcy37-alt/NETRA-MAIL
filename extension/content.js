// ============================================================
// NETRA-MAIL SHIELD
// Gmail Real-Time Protection
// ============================================================

let protectionEnabled = false;

let lastEmailKey = "";

let scanning = false;

let scanTimer = null;


// ============================================================
// LOAD PROTECTION STATE
// ============================================================

function loadProtectionState() {

    chrome.storage.local.get(
        ["netraProtectionEnabled"],
        (result) => {

            protectionEnabled =
                result.netraProtectionEnabled !== false;

            if (typeof result.netraProtectionEnabled !== "boolean") {
                chrome.storage.local.set({netraProtectionEnabled: true});
            }


            if (!protectionEnabled) {

                removeNetraBadge();

                lastEmailKey = "";

                return;
            }


            // Analysis is explicitly initiated by the user from the popup.
        }
    );
}


// ============================================================
// STORAGE CHANGE LISTENER
// ============================================================

chrome.storage.onChanged.addListener(
    (changes, areaName) => {

        if (
            areaName !== "local" ||
            !changes.netraProtectionEnabled
        ) {
            return;
        }


        protectionEnabled =
            changes.netraProtectionEnabled.newValue === true;


        if (!protectionEnabled) {

            removeNetraBadge();

            lastEmailKey = "";

            return;
        }


        lastEmailKey = "";

        // Do not automatically extract email content after a preference change.
    }
);


// ============================================================
// INITIALIZE
// ============================================================

loadProtectionState();


// Email contents are accessed only after an explicit popup action. This is a
// privacy control: Gmail DOM changes alone never trigger data transmission.


// ============================================================
// SUBJECT
// ============================================================

function findSubjectElement() {

    const selectors = [
        "h2.hP",
        "h2[data-thread-perm-id]",
        "div.hP"
    ];


    for (const selector of selectors) {

        const element =
            document.querySelector(selector);


        if (
            element &&
            (
                element.innerText ||
                element.textContent
            )
        ) {

            return element;
        }
    }


    return null;
}


// ============================================================
// SENDER
// ============================================================

function findSenderElement(root) {

    const selectors = [
        "span.gD[email]",
        "span[email]",
        ".gD"
    ];


    for (const selector of selectors) {

        const elements =
            root.querySelectorAll(selector);


        for (const element of elements) {

            const email =
                element.getAttribute("email");


            if (
                email &&
                email.includes("@")
            ) {

                return element;
            }
        }
    }


    return null;
}


// ============================================================
// BODY
// ============================================================

function findBodyElement() {

    const bodies =
        document.querySelectorAll(
            "div.a3s"
        );


    if (!bodies.length) {
        return null;
    }


    for (
        let i = bodies.length - 1;
        i >= 0;
        i--
    ) {

        const body =
            bodies[i];


        const text =
            body.innerText ||
            body.textContent ||
            "";


        if (
            text.trim().length > 10 &&
            isVisible(body)
        ) {

            return body;
        }
    }


    return null;
}


// ============================================================
// VISIBILITY
// ============================================================

function isVisible(element) {

    if (!element) {
        return false;
    }


    const rect =
        element.getBoundingClientRect();


    return (
        rect.width > 0 &&
        rect.height > 0
    );
}


// ============================================================
// EMAIL EXTRACTION
// ============================================================

function extractCurrentEmail() {

    const subjectEl =
        findSubjectElement();

    const bodyEl =
        findBodyElement();

    // Keep sender and body within the same Gmail message in a conversation.
    const messageRoot = bodyEl && bodyEl.closest(".adn");
    const senderEl = messageRoot && findSenderElement(messageRoot);


    if (
        !subjectEl ||
        !senderEl ||
        !bodyEl
    ) {
        return null;
    }


    const subject =
        Array.from(subjectEl.childNodes)
            .filter(node => node.id !== "netra-mail-badge")
            .map(node => node.textContent || "").join("").trim();


    let sender =
        senderEl.getAttribute(
            "email"
        );


    if (!sender) {

        sender =
            (
                senderEl.innerText ||
                ""
            ).trim();
    }


    const body =
        (
            bodyEl.innerText ||
            bodyEl.textContent ||
            ""
        ).trim();


    if (
        !subject ||
        !sender ||
        !body
    ) {
        return null;
    }


    // --------------------------------------------------------
    // Gmail recipient
    // --------------------------------------------------------

    let recipient = "";

    const recipientSelectors = [
        "span.g2[email]"
    ];


    for (
        const selector
        of recipientSelectors
    ) {

        const elements =
            messageRoot.querySelectorAll(
                selector
            );


        for (
            const element
            of elements
        ) {

            const email =
                element.getAttribute(
                    "email"
                );


            if (
                email &&
                email.includes("@") &&
                email !== sender
            ) {

                recipient = email;

                break;
            }
        }


        if (recipient) {
            break;
        }
    }


    // --------------------------------------------------------
    // HTML
    // --------------------------------------------------------

    let html = "";

    if (bodyEl) {

        html =
            bodyEl.innerHTML ||
            "";
    }


    // Limit payload size before sending
    html =
        html.slice(
            0,
            500000
        );


    return {
        subject,
        sender,
        recipient,
        reply_to: "",
        body: body.slice(0, 500000),
        html
    };
}


// ============================================================
// EMAIL KEY
// ============================================================

function createEmailKey(
    subject,
    sender,
    body,
    html = "",
    recipient = ""
) {

    const raw =
        JSON.stringify([subject, sender, body, html, recipient]);

    // Exact comparison avoids truncated-body and short-hash collisions.
    return raw;
}


// ============================================================
// MAIN SCAN
// ============================================================

async function scanCurrentEmail() {

    if (!protectionEnabled) {
        throw new Error("Enable Email Protection before analyzing an email.");
    }


    if (scanning) {
        throw new Error("An analysis is already in progress.");
    }


    const email =
        extractCurrentEmail();


    if (!email) {
        throw new Error("Open a single Gmail email with a visible sender, subject, and body.");
    }


    const emailKey =
        createEmailKey(
            email.subject,
            email.sender,
            email.body,
            email.html,
            email.recipient
        );


    lastEmailKey =
        emailKey;


    showScanningBadge(findSubjectElement());


    scanning = true;


    try {

        const result =
            await analyzeThroughBackground(
                email
            );


        const normalized =
            normalizeResult(
                result
            );

        if (!protectionEnabled) throw new Error("Analysis was disabled before the result arrived.");
        const current = extractCurrentEmail();
        if (!current || createEmailKey(current.subject, current.sender, current.body, current.html, current.recipient) !== emailKey) {
            removeNetraBadge();
            throw new Error("The open message changed during analysis. Analyze the current message again.");
        }


        if (!normalized) {

            throw new Error(
                "Invalid NETRA response."
            );
        }


        renderThreatBadge(
            findSubjectElement(),
            normalized
        );

        return normalized;

    }
    catch (error) {

        console.error(
            "[NETRA] Scan failed:",
            error
        );


        removeNetraBadge();

        throw error;

    }
    finally {

        scanning = false;
    }
}


// ============================================================
// EXPLICIT USER-INITIATED ANALYSIS
// ============================================================

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (!message || message.type !== "NETRA_ANALYZE_CURRENT_EMAIL") {
        return;
    }
    if (!protectionEnabled) {
        sendResponse({success: false, error: "Enable Email Protection before analyzing an email."});
        return;
    }
    scanCurrentEmail()
        .then(result => sendResponse({success: true, result}))
        .catch(error => sendResponse({success: false, error: error.message}));
    return true;
});


// ============================================================
// BACKGROUND API BRIDGE
// ============================================================

function analyzeThroughBackground(
    email
) {

    return new Promise(
        (
            resolve,
            reject
        ) => {

            chrome.runtime.sendMessage(
                {
                    type:
                        "NETRA_ANALYZE_EMAIL",

                    email
                },

                (response) => {

                    if (
                        chrome.runtime.lastError
                    ) {

                        reject(
                            new Error(
                                chrome.runtime.lastError.message
                            )
                        );

                        return;
                    }


                    if (
                        !response
                    ) {

                        reject(
                            new Error(
                                "No response from NETRA background service."
                            )
                        );

                        return;
                    }


                    if (
                        !response.success
                    ) {

                        reject(
                            new Error(
                                response.error ||
                                "NETRA backend request failed."
                            )
                        );

                        return;
                    }


                    resolve(
                        response.data
                    );
                }
            );
        }
    );
}


// ============================================================
// RESULT NORMALIZATION
// ============================================================

function normalizeResult(data) {

    if (!data) {
        return null;
    }
    if (data.risk_score == null && data.score == null && (!data.decision || data.decision.score == null)) return null;


    const decision =
        data.decision ||
        {};


    const score =
        Number(
            decision.score ??
            data.risk_score ??
            data.score ??
            0
        );


    const riskLevel =
        String(
            decision.risk_level ??
            decision.risk ??
            (score >= 75 ? "CRITICAL" : score >= 50 ? "HIGH" : score >= 25 ? "LOW" : "LOW RISK") ??
            "UNKNOWN"
        ).toUpperCase();


    const action =
        String(
            decision.action ??
            "REVIEW"
        ).toUpperCase();


    let confidence =
        Number(
            decision.confidence ??
            data.confidence ??
            0
        );

    if (!data.decision && confidence <= 1) confidence *= 100;
    if (!Number.isFinite(score) || score < 0 || score > 100 || !Number.isFinite(confidence)) return null;


    const classification =
        String(
            decision.attack_classification ??
            decision.classification ??
            data.classification ??
            "Unknown"
        );


    return {
        score,
        riskLevel,
        action,
        confidence,
        classification,
        emailId: String(data.email_id || ""),
        dashboardUrl: String(data.dashboard_url || ""),
        raw: data
    };
}


// ============================================================
// SCANNING BADGE
// ============================================================

function showScanningBadge(
    subjectEl
) {

    if (!subjectEl) {
        return;
    }

    const oldLink = document.getElementById("netra-mail-report-link");
    if (oldLink) oldLink.remove();


    let badge =
        document.getElementById(
            "netra-mail-badge"
        );


    if (!badge) {

        badge =
            document.createElement(
                "span"
            );

        badge.id =
            "netra-mail-badge";


        badge.style.cssText = `
            display:inline-flex;
            align-items:center;
            margin-left:12px;
            padding:5px 10px;
            border-radius:999px;
            background:#1e293b;
            color:#7dd3fc;
            font-family:Arial,sans-serif;
            font-size:12px;
            font-weight:700;
            z-index:999999;
        `;


        subjectEl.appendChild(
            badge
        );
    }


    badge.textContent =
        "🛡️ NETRA SCANNING...";
}


// ============================================================
// THREAT BADGE
// ============================================================

function renderThreatBadge(
    subjectEl,
    result
) {

    if (!subjectEl) {
        return;
    }


    let badge =
        document.getElementById(
            "netra-mail-badge"
        );


    if (!badge) {

        badge =
            document.createElement(
                "span"
            );

        badge.id =
            "netra-mail-badge";


        subjectEl.appendChild(
            badge
        );
    }


    let background =
        "#166534";

    let foreground =
        "#dcfce7";


    if (
        result.score >= 75 ||
        result.riskLevel === "CRITICAL"
    ) {

        background =
            "#991b1b";

        foreground =
            "#fee2e2";

    }
    else if (
        result.score >= 50 ||
        result.riskLevel === "HIGH"
    ) {

        background =
            "#9a3412";

        foreground =
            "#ffedd5";

    }
    else if (
        result.score >= 25 ||
        result.riskLevel === "LOW"
    ) {

        background =
            "#854d0e";

        foreground =
            "#fef9c3";
    }


    badge.style.cssText = `
        display:inline-flex;
        align-items:center;
        gap:5px;
        margin-left:12px;
        padding:5px 10px;
        border-radius:999px;
        background:${background};
        color:${foreground};
        font-family:Arial,sans-serif;
        font-size:12px;
        font-weight:700;
        z-index:999999;
    `;


    badge.textContent =
        `🛡️ NETRA ${result.riskLevel} • ${result.score}/100 • ${result.action}`;


    badge.title =
        `${result.classification} | Confidence ${result.confidence}%`;

    const oldLink = document.getElementById("netra-mail-report-link");
    if (oldLink) oldLink.remove();
    if (result.dashboardUrl) {
        const reportLink = document.createElement("a");
        reportLink.id = "netra-mail-report-link";
        reportLink.href = result.dashboardUrl;
        reportLink.target = "_blank";
        reportLink.rel = "noopener noreferrer";
        reportLink.textContent = "View forensic report";
        reportLink.title = "Open this email investigation in the NETRA SOC dashboard";
        reportLink.style.cssText = `
            display:inline-flex;
            align-items:center;
            margin-left:8px;
            color:#0b57d0;
            font-family:Arial,sans-serif;
            font-size:12px;
            font-weight:700;
            text-decoration:underline;
            white-space:nowrap;
        `;
        subjectEl.appendChild(reportLink);
    }
}


// ============================================================
// ERROR BADGE
// ============================================================

function renderErrorBadge(
    subjectEl,
    message
) {

    if (!subjectEl) {
        return;
    }


    let badge =
        document.getElementById(
            "netra-mail-badge"
        );


    if (!badge) {

        badge =
            document.createElement(
                "span"
            );

        badge.id =
            "netra-mail-badge";


        subjectEl.appendChild(
            badge
        );
    }


    badge.style.cssText = `
        display:inline-flex;
        align-items:center;
        margin-left:12px;
        padding:5px 10px;
        border-radius:999px;
        background:#334155;
        color:#cbd5e1;
        font-family:Arial,sans-serif;
        font-size:12px;
        font-weight:700;
        z-index:999999;
    `;


    badge.textContent =
        "⚠️ NETRA SCAN UNAVAILABLE";


    badge.title =
        message ||
        "NETRA backend is unavailable.";
}


// ============================================================
// REMOVE BADGE
// ============================================================

function removeNetraBadge() {

    const badge =
        document.getElementById(
            "netra-mail-badge"
        );


    if (badge) {
        badge.remove();
    }
    const reportLink = document.getElementById("netra-mail-report-link");
    if (reportLink) reportLink.remove();
}
