/* =========================================================
   PHISHLENS — DEMON CORE ANALYZER
========================================================= */

const emailInput = document.getElementById("emailInput");
const charCount = document.getElementById("charCount");

/* =========================================================
   CHARACTER COUNTER
========================================================= */

emailInput.addEventListener("input", () => {
    const count = emailInput.value.length;

    charCount.textContent = `${count} characters`;

    if (count > 0) {
        charCount.style.color = "#9f1728";
    } else {
        charCount.style.color = "";
    }
});


/* =========================================================
   CLEAR
========================================================= */

function clearEmail() {

    emailInput.value = "";

    charCount.textContent = "0 characters";

    charCount.style.color = "";

    document
        .getElementById("resultsSection")
        .classList.add("hidden");
}


/* =========================================================
   SENDER EXTRACTION
========================================================= */

function extractSender(text) {

    const match = text.match(
        /(?:From|Sender)\s*:\s*(?:.*?<)?([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})/i
    );

    if (match) {
        return match[1];
    }

    const emailMatch = text.match(
        /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i
    );

    return emailMatch
        ? emailMatch[0]
        : "Not detected";
}


/* =========================================================
   IP EXTRACTION
========================================================= */

function extractIP(text) {

    const ips = text.match(
        /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
    );

    if (!ips) {
        return null;
    }

    for (const ip of ips) {

        const parts = ip.split(".").map(Number);

        const valid = parts.every(
            number => number >= 0 && number <= 255
        );

        if (!valid) continue;

        if (
            parts[0] === 10 ||
            parts[0] === 127 ||
            (parts[0] === 192 && parts[1] === 168) ||
            (
                parts[0] === 172 &&
                parts[1] >= 16 &&
                parts[1] <= 31
            )
        ) {
            continue;
        }

        return ip;
    }

    return null;
}


/* =========================================================
   DOMAIN
========================================================= */

function extractDomain(email) {

    if (!email || email === "Not detected") {
        return "Not detected";
    }

    const parts = email.split("@");

    return parts.length === 2
        ? parts[1].toLowerCase()
        : "Not detected";
}


/* =========================================================
   LINKS
========================================================= */

function extractLinks(text) {

    const links = text.match(
        /https?:\/\/[^\s<>"']+/gi
    );

    return links || [];
}


/* =========================================================
   SUSPICIOUS DOMAIN
========================================================= */

function suspiciousDomain(domain) {

    if (!domain || domain === "Not detected") {
        return false;
    }

    const suspiciousWords = [
        "verify",
        "secure",
        "security",
        "account",
        "support",
        "login",
        "update",
        "confirm",
        "wallet",
        "payment"
    ];

    const lower = domain.toLowerCase();

    return suspiciousWords.some(
        word => lower.includes(word)
    );
}


/* =========================================================
   URL ANALYSIS
========================================================= */

function analyzeLinks(links) {

    let score = 0;

    let findings = [];

    if (links.length > 0) {

        findings.push(
            `${links.length} URL(s) detected`
        );

        score += Math.min(
            15,
            links.length * 5
        );
    }

    links.forEach(link => {

        const lower = link.toLowerCase();

        if (
            lower.includes("@") ||
            lower.includes("login") ||
            lower.includes("verify") ||
            lower.includes("secure") ||
            lower.includes("account")
        ) {

            score += 8;

            findings.push(
                "Potential credential-harvesting URL pattern"
            );
        }

        if (lower.startsWith("http://")) {

            score += 5;

            findings.push(
                "Unencrypted HTTP link detected"
            );
        }
    });

    return {
        score: Math.min(score, 30),
        findings
    };
}


/* =========================================================
   LANGUAGE ANALYSIS
========================================================= */

function analyzeLanguage(text) {

    let score = 0;

    const findings = [];

    const urgentWords = [
        "urgent",
        "immediately",
        "act now",
        "final warning",
        "account suspended",
        "account locked",
        "verify now",
        "within 24 hours",
        "action required"
    ];

    const financialWords = [
        "bank",
        "payment",
        "credit card",
        "debit card",
        "transaction",
        "refund",
        "money",
        "wallet"
    ];

    const credentialWords = [
        "password",
        "login",
        "username",
        "otp",
        "verification code",
        "credentials"
    ];

    urgentWords.forEach(word => {

        if (text.includes(word)) {

            score += 8;

            findings.push(
                `Urgency indicator: "${word}"`
            );
        }
    });

    financialWords.forEach(word => {

        if (text.includes(word)) {

            score += 4;

            findings.push(
                `Financial keyword detected: "${word}"`
            );
        }
    });

    credentialWords.forEach(word => {

        if (text.includes(word)) {

            score += 6;

            findings.push(
                `Credential-related keyword: "${word}"`
            );
        }
    });

    return {
        score: Math.min(score, 35),
        findings
    };
}


/* =========================================================
   HEADER ANALYSIS
========================================================= */

function analyzeHeaders(text) {

    let score = 0;

    const findings = [];

    const lower = text.toLowerCase();

    if (
        lower.includes("spf=fail") ||
        lower.includes("spf: fail")
    ) {

        score += 15;

        findings.push(
            "SPF authentication failure detected"
        );
    }

    if (
        lower.includes("dkim=fail") ||
        lower.includes("dkim: fail")
    ) {

        score += 15;

        findings.push(
            "DKIM authentication failure detected"
        );
    }

    if (
        lower.includes("dmarc=fail") ||
        lower.includes("dmarc: fail")
    ) {

        score += 15;

        findings.push(
            "DMARC authentication failure detected"
        );
    }

    if (lower.includes("reply-to:")) {

        score += 4;

        findings.push(
            "Reply-To header present; verify destination"
        );
    }

    return {
        score: Math.min(score, 40),
        findings
    };
}


/* =========================================================
   ATTACHMENT ANALYSIS
========================================================= */

function analyzeAttachments(text) {

    let score = 0;

    const findings = [];

    const dangerousExtensions = [
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".js",
        ".vbs",
        ".ps1",
        ".msi"
    ];

    const lower = text.toLowerCase();

    dangerousExtensions.forEach(extension => {

        if (lower.includes(extension)) {

            score += 15;

            findings.push(
                `Potentially risky attachment type referenced: ${extension}`
            );
        }
    });

    if (lower.includes("attachment")) {

        findings.push(
            "Email references an attachment"
        );
    }

    return {
        score: Math.min(score, 20),
        findings
    };
}


/* =========================================================
   RISK LEVEL
========================================================= */

function getRiskLevel(score) {

    if (score <= 30) {

        return {
            label: "SAFE",
            color: "#49d98a",
            description:
                "No significant threat indicators detected."
        };
    }

    if (score <= 60) {

        return {
            label: "SUSPICIOUS",
            color: "#e7ae43",
            description:
                "Several indicators require further verification."
        };
    }

    return {
        label: "DANGER",
        color: "#ff263f",
        description:
            "Multiple high-risk indicators were detected."
    };
}


/* =========================================================
   GEOLOCATION
========================================================= */

async function getGeoLocation(ip) {

    if (!ip) {

        return {
            location: "No public IP found",
            organization: "Unavailable"
        };
    }

    try {

        const response = await fetch(
            `https://ipapi.co/${ip}/json/`
        );

        if (!response.ok) {
            throw new Error("Location unavailable");
        }

        const data = await response.json();

        return {

            location:
                `${data.city || "Unknown city"}, ${data.country_name || "Unknown country"}`,

            organization:
                data.org || "Unknown network"
        };

    } catch (error) {

        return {
            location: "Lookup unavailable",
            organization: "Unknown"
        };
    }
}


/* =========================================================
   CINEMATIC SCAN EFFECT
========================================================= */

function startScanEffect() {

    const button =
        document.querySelector(".scan-button");

    button.innerHTML = `
        <span class="scan-icon">◉</span>
        <span>SCANNING THREAT SIGNATURE...</span>
    `;

    button.style.boxShadow =
        "0 0 35px rgba(255,20,40,.35)";
}


/* =========================================================
   FORENSIC REPORT
========================================================= */

function generateForensicReport(
    score,
    risk,
    sender,
    ip,
    location,
    findings
) {

    const timestamp =
        new Date().toLocaleString();

    let report = "";

    report +=
        `[+] PHISHLENS FORENSIC ANALYSIS\n\n`;

    report +=
        `TIMESTAMP      : ${timestamp}\n`;

    report +=
        `THREAT SCORE   : ${score}/100\n`;

    report +=
        `CLASSIFICATION : ${risk.label}\n`;

    report +=
        `SENDER         : ${sender}\n`;

    report +=
        `SOURCE IP      : ${ip || "Not found"}\n`;

    report +=
        `GEOLOCATION    : ${location}\n\n`;

    report +=
        `----------------------------------------\n`;

    report +=
        `THREAT INDICATORS\n`;

    report +=
        `----------------------------------------\n\n`;

    if (findings.length === 0) {

        report +=
            `[OK] No major indicators detected.\n`;

    } else {

        findings.forEach(
            (finding, index) => {

                report +=
                    `[${String(index + 1).padStart(2, "0")}] ${finding}\n`;
            }
        );
    }

    report +=
        `\n----------------------------------------\n`;

    report +=
        `ANALYST ASSESSMENT\n`;

    report +=
        `----------------------------------------\n\n`;

    if (score <= 30) {

        report +=
            `The email currently presents a low-risk profile.\n`;

        report +=
            `Continue to verify the sender before interacting with sensitive content.\n`;

    } else if (score <= 60) {

        report +=
            `The email contains suspicious characteristics.\n`;

        report +=
            `Independent verification of the sender and links is recommended.\n`;

    } else {

        report +=
            `The email contains multiple high-risk characteristics.\n`;

        report +=
            `Treat the message as potentially malicious and avoid interacting with links or attachments.\n`;
    }

    report +=
        `\n[!] Prototype heuristic analysis — not a definitive malware verdict.`;

    return report;
}


/* =========================================================
   MAIN ANALYSIS
========================================================= */

async function analyzeEmail() {

    const text =
        emailInput.value.trim();

    if (!text) {

        alert(
            "Please paste an email or raw email headers first."
        );

        return;
    }

    const button =
        document.querySelector(".scan-button");

    button.disabled = true;

    startScanEffect();

    /* Dramatic processing sequence */

    await new Promise(
        resolve => setTimeout(resolve, 350)
    );

    button.innerHTML = `
        <span>◈</span>
        <span>ISOLATING EMAIL ARTIFACTS...</span>
    `;

    await new Promise(
        resolve => setTimeout(resolve, 350)
    );

    button.innerHTML = `
        <span>◈</span>
        <span>ANALYZING THREAT SIGNATURES...</span>
    `;

    await new Promise(
        resolve => setTimeout(resolve, 450)
    );

    /* Extract */

    const sender =
        extractSender(text);

    const domain =
        extractDomain(sender);

    const ip =
        extractIP(text);

    const links =
        extractLinks(text);

    /* Analyze */

    const language =
        analyzeLanguage(text.toLowerCase());

    const headers =
        analyzeHeaders(text);

    const urlAnalysis =
        analyzeLinks(links);

    const attachments =
        analyzeAttachments(text);

    /* Domain */

    let domainScore = 0;

    let domainFindings = [];

    if (suspiciousDomain(domain)) {

        domainScore += 12;

        domainFindings.push(
            "Sender domain contains security-related or account-related wording"
        );
    }

    /* Findings */

    const findings = [

        ...language.findings,

        ...headers.findings,

        ...urlAnalysis.findings,

        ...attachments.findings,

        ...domainFindings

    ];

    let score =
        language.score +
        headers.score +
        urlAnalysis.score +
        attachments.score +
        domainScore;

    score = Math.min(score, 100);

    const risk =
        getRiskLevel(score);

    /* Geo */

    const geo =
        await getGeoLocation(ip);

    /* Display */

    displayResults(
        score,
        risk,
        sender,
        ip,
        domain,
        geo,
        findings
    );

    /* Restore */

    button.innerHTML = `
        <span class="scan-icon">◉</span>
        <span>ANALYZE EMAIL</span>
        <span class="arrow">→</span>
    `;

    button.style.boxShadow = "";

    button.disabled = false;
}


/* =========================================================
   DISPLAY RESULTS
========================================================= */

function displayResults(
    score,
    risk,
    sender,
    ip,
    domain,
    geo,
    findings
) {

    const section =
        document.getElementById("resultsSection");

    section.classList.remove("hidden");

    /* Score */

    const scoreValue =
        document.getElementById("scoreValue");

    scoreValue.textContent = "0";

    animateNumber(
        scoreValue,
        score
    );

    document.getElementById("riskStatus")
        .textContent = risk.label;

    document.getElementById("riskStatus")
        .style.color = risk.color;

    document.getElementById("riskDescription")
        .textContent = risk.description;

    document.getElementById("riskBadge")
        .textContent = risk.label;

    document.getElementById("riskBadge")
        .style.color = risk.color;

    /* Score circle */

    const degrees =
        score * 3.6;

    document.getElementById("scoreCircle")
        .style.background =
            `conic-gradient(
                ${risk.color} 0deg,
                ${risk.color} ${degrees}deg,
                rgba(255,255,255,0.04) ${degrees}deg
            )`;

    document.getElementById("scoreCircle")
        .style.boxShadow =
            `0 0 45px ${risk.color}33`;

    /* Intelligence */

    document.getElementById("senderInfo")
        .textContent = sender;

    document.getElementById("ipInfo")
        .textContent =
            ip || "Not detected";

    document.getElementById("domainInfo")
        .textContent = domain;

    document.getElementById("locationInfo")
        .textContent = geo.location;

    /* Indicators */

    const indicatorList =
        document.getElementById("indicatorList");

    indicatorList.innerHTML = "";

    if (findings.length === 0) {

        findings = [
            "No significant threat indicators detected"
        ];
    }

    findings
        .slice(0, 8)
        .forEach((finding, index) => {

            const div =
                document.createElement("div");

            div.className = "indicator";

            div.style.animationDelay =
                `${index * 70}ms`;

            div.innerHTML = `
                <div class="indicator-icon">⚠</div>
                <span>${escapeHTML(finding)}</span>
            `;

            indicatorList.appendChild(div);
        });

    /* Report ID */

    const reportId =
        "MS-" +
        Date.now()
            .toString()
            .slice(-6);

    document.getElementById("reportId")
        .textContent = reportId;

    /* Forensic report */

    const report =
        generateForensicReport(
            score,
            risk,
            sender,
            ip || "Not detected",
            geo.location,
            findings
        );

    typeTerminalText(report);

    /* Recommendation */

    const recommendationText =
        document.getElementById(
            "recommendationText"
        );

    if (score <= 30) {

        recommendationText.textContent =
            "The message appears low risk. Still verify the sender before sharing sensitive information.";

    } else if (score <= 60) {

        recommendationText.textContent =
            "Verify the sender through an independent channel. Avoid clicking unfamiliar links or opening unexpected attachments.";

    } else {

        recommendationText.textContent =
            "High-risk indicators detected. Do not interact with suspicious links, attachments, or requests for sensitive information.";
    }

    document.getElementById("recommendation")
        .style.borderColor = risk.color;

    /* Time */

    document.getElementById("analysisTime")
        .textContent =
            `Analyzed ${new Date().toLocaleTimeString()}`;

    /* Cinematic reveal */

    section.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}


/* =========================================================
   SCORE COUNTER
========================================================= */

function animateNumber(element, target) {

    let current = 0;

    const duration = 1000;

    const start =
        performance.now();

    function update(time) {

        const progress =
            Math.min(
                (time - start) / duration,
                1
            );

        const eased =
            1 - Math.pow(1 - progress, 3);

        current =
            Math.round(target * eased);

        element.textContent =
            current;

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}


/* =========================================================
   TERMINAL TYPEWRITER
========================================================= */

function typeTerminalText(text) {

    const terminal =
        document.getElementById(
            "forensicReport"
        );

    terminal.textContent = "";

    let index = 0;

    const speed = 3;

    function type() {

        if (index < text.length) {

            terminal.textContent +=
                text.charAt(index);

            index++;

            setTimeout(type, speed);

        }
    }

    type();
}


/* =========================================================
   HTML ESCAPE
========================================================= */

function escapeHTML(value) {

    return value
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/* =========================================================
   DOWNLOAD FORENSIC REPORT
========================================================= */

function downloadReport() {

    const report =
        document.getElementById("forensicReport").textContent;

    if (
        !report ||
        report.trim() === "" ||
        report.includes("Waiting for analysis")
    ) {
        alert("Analyze an email first to generate the report.");
        return;
    }

    const reportId =
        document.getElementById("reportId").textContent;

    const blob = new Blob(
        [report],
        { type: "text/plain;charset=utf-8" }
    );

    const url =
        URL.createObjectURL(blob);

    const link =
        document.createElement("a");

    link.href = url;

    link.download =
        `PhishLens-${reportId}.txt`;

    document.body.appendChild(link);

    link.click();

    document.body.removeChild(link);

    URL.revokeObjectURL(url);
}