document.addEventListener("DOMContentLoaded", () => {

    applyStoredTheme();

    const params = new URLSearchParams(window.location.search);

    const url = params.get("url") || "Unknown";

    const score = params.get("score") || "0";

    const severity = params.get("severity") || "SAFE";

    const explanation =
        params.get("explanation") ||
        "No explanation available.";

    let indicators = [];

    try {

        indicators = JSON.parse(
            decodeURIComponent(
                params.get("indicators") || "[]"
            )
        );

    } catch {

        indicators = [];

    }

    document.getElementById("website").textContent = url;

    document.getElementById("score").textContent = score + "/100";

    document.getElementById("severity").textContent = severity;

    document.getElementById("explanation").textContent = explanation;

    const list = document.getElementById("indicatorList");

    if (indicators.length === 0) {

        const li = document.createElement("li");

        li.textContent = "No threat indicators available.";

        list.appendChild(li);

    } else {

        indicators.forEach(ind => {

            const li = document.createElement("li");

            li.textContent = ind;

            list.appendChild(li);

        });

    }

    document.getElementById("backBtn").onclick = () => {

        history.back();

    };

    document.getElementById("dashboardBtn").onclick = () => {
        // Read from config.js (injected via <script> in warning.html)
        const url = (typeof SCYTHE_CONFIG !== "undefined")
            ? SCYTHE_CONFIG.DASHBOARD_URL
            : "http://localhost:8000/dashboard";
        window.open(url, "_blank");
    };

    document.getElementById("continueBtn").onclick = () => {

        const ok = confirm(
            "This website has been marked as dangerous.\n\nAre you sure you want to continue?"
        );

        if (ok) {

            chrome.runtime.sendMessage({ type: "ALLOW_SITE", url }, () => {
                window.location.href = url;
            });

        }

    };

});

function applyStoredTheme() {

    chrome.storage.sync.get(["theme"], (result) => {

        document.documentElement.setAttribute(
            "data-theme",
            result?.theme === "light" ? "light" : "dark"
        );

    });

}

chrome.storage.onChanged.addListener((changes, area) => {

    if (area !== "sync") return;

    if (!changes.theme) return;

    document.documentElement.setAttribute(
        "data-theme",
        changes.theme.newValue === "light" ? "light" : "dark"
    );

});