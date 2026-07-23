// ============================================================
// AEGIS — content.js
// DOM Structure Scanner
// Detects phishing indicators from page structure.
// Sends BDR_EVENTS and BDR_CRITICAL messages to background.js
// ============================================================

let indicators = [];
let score = 0;

// -------------------------
// Utility Functions
// -------------------------

function addIndicator(name, points) {
    if (!indicators.includes(name)) {
        indicators.push(name);
        score += points;
    }
}

function sendResults() {

    score = Math.min(score, 100);

    const events = indicators.map(ind => ({
        event_type: ind,
        details: { score },
        timestamp: new Date().toISOString()
    }));

    chrome.runtime.sendMessage({
        type: "BDR_EVENTS",
        events
    });

}

// -------------------------
// 1. Password over HTTP
// -------------------------

if (
    location.protocol === "http:" &&
    document.querySelector('input[type="password"]')
) {
    addIndicator("Password field on HTTP page", 40);
}

// -------------------------
// 2. Hidden iFrames
// -------------------------

document.querySelectorAll("iframe").forEach(frame => {

    const style = window.getComputedStyle(frame);

    if (
        style.display === "none" ||
        style.visibility === "hidden" ||
        frame.width <= 2 ||
        frame.height <= 2
    ) {
        addIndicator("Hidden iframe detected", 20);
    }

});

// -------------------------
// 3. External Form Actions
// -------------------------

document.querySelectorAll("form").forEach(form => {

    const action = form.action;

    if (!action) return;

    try {

        const actionURL = new URL(action, location.href);

        if (actionURL.hostname !== location.hostname) {

            addIndicator("Form submits to external domain", 25);

        }

    } catch {}

});

// -------------------------
// 4. Multiple Password Fields
// -------------------------

const passwordFields =
document.querySelectorAll('input[type="password"]');

if (passwordFields.length > 1) {

    addIndicator("Multiple password fields", 10);

}

// -------------------------
// 5. Suspicious Keywords
// -------------------------

const suspiciousWords = [

    "verify",
    "secure",
    "confirm",
    "update",
    "login",
    "signin",
    "wallet",
    "bank"

];

const pageText =
document.body.innerText.toLowerCase();

if (
    suspiciousWords.some(word => pageText.includes(word))
) {

    addIndicator("Suspicious phishing keywords", 10);

}

// -------------------------
// 6. Hidden Inputs
// -------------------------

const hiddenInputs =
document.querySelectorAll('input[type="hidden"]');

if (hiddenInputs.length >= 5) {

    addIndicator("Excessive hidden inputs", 10);

}

// -------------------------
// 7. Full Screen Overlay
// -------------------------

document.querySelectorAll("*").forEach(el => {

    const style = window.getComputedStyle(el);

    if (
        style.position === "fixed"
        &&
        parseFloat(style.width) >= window.innerWidth * 0.9
        &&
        parseFloat(style.height) >= window.innerHeight * 0.9
    ) {

        addIndicator("Fullscreen overlay", 15);

    }

});

// -------------------------
// 8. Suspicious Links
// -------------------------

document.querySelectorAll("a").forEach(link => {

    if (!link.href) return;

    try {

        const url = new URL(link.href);

        if (
            url.hostname !== location.hostname &&
            url.protocol === "http:"
        ) {

            addIndicator("HTTP external links", 10);

        }

    } catch {}

});

// -------------------------
// 9. Fake Login Detection
// -------------------------

const loginInputs =
document.querySelectorAll(
'input[type="password"],input[type="email"],input[name*=user i]'
);

if (loginInputs.length >= 2) {

    addIndicator("Possible login page", 15);

}

// -------------------------
// 10. Mutation Observer
// -------------------------

const observer =
new MutationObserver(() => {

    document
        .querySelectorAll('iframe')
        .forEach(frame => {

            const style =
            getComputedStyle(frame);

            if (
                style.display === "none"
            ) {

                addIndicator(
                    "Dynamic hidden iframe",
                    20
                );

            }

        });

});

observer.observe(document.documentElement, {

    childList: true,
    subtree: true

});

// -------------------------
// Critical Detection
// -------------------------

if (
    location.protocol === "http:" &&
    passwordFields.length
) {

    chrome.runtime.sendMessage({

        type: "BDR_CRITICAL",

        alert_type: "Credentials requested over HTTP",

        details: {
            reason: "Critical phishing indicator detected (credentials requested over HTTP)."
        }

    });

}

// -------------------------
// Send Initial Report
// -------------------------

sendResults();

// -------------------------
// Re-scan after page settles
// -------------------------

setTimeout(sendResults, 3000);