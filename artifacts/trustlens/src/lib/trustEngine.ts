export interface TrustSignal {
  label: string;
  description: string;
  impact: number;
  category: "url" | "content" | "behavior" | "technical";
  severity: "positive" | "warning" | "danger";
}

export interface TrustResult {
  score: number;
  riskLevel: "Safe" | "Suspicious" | "Dangerous";
  signals: TrustSignal[];
  inputType: "url" | "message" | "email" | "phone" | "unknown";
  summary: string;
  recommendation: string;
  analysisTime: number;
  fingerprint: string;
}

const SPAM_KEYWORDS = [
  "urgent", "act now", "click now", "click here", "limited time", "offer expires",
  "winner", "won", "win", "prize", "free", "congratulations", "claim",
  "verify account", "suspended", "blocked", "unusual activity", "login attempt",
  "confirm identity", "update payment", "bank details", "credit card",
  "password expired", "account locked", "security alert", "immediate action",
  "100%", "guaranteed", "risk-free", "no risk", "double your", "earn money",
  "work from home", "make money fast", "get rich", "million dollar",
  "nigerian prince", "inheritance", "transfer funds", "wire transfer",
  "bitcoin", "crypto investment", "forex", "pump and dump",
  "you have been selected", "exclusively for you", "special offer",
  "unsubscribe", "opt-out", "remove me", "click below", "open attachment",
  "download now", "install now", "run this", "execute", "admin password",
];

const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
  "tiny.cc", "is.gd", "cli.gs", "pic.gd", "digg.com", "tr.im",
  "short.to", "ur1.ca", "shrinkr.com", "miniurl.com", "snurl.com",
  "su.pr", "lnk.in", "shorte.st", "linktr.ee", "rb.gy", "cutt.ly",
  "tiny.one", "shorturl.at", "qlink.me", "sh.st", "adf.ly",
];

const TRUSTED_DOMAINS = [
  "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com",
  "wikipedia.org", "youtube.com", "linkedin.com", "twitter.com", "x.com",
  "facebook.com", "instagram.com", "reddit.com", "stackoverflow.com",
  "mozilla.org", "cloudflare.com", "stripe.com", "paypal.com",
  "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
];

const SUSPICIOUS_TLD = [
  ".xyz", ".top", ".club", ".online", ".site", ".website", ".host",
  ".pw", ".cc", ".su", ".tk", ".ml", ".ga", ".cf", ".gq",
  ".icu", ".work", ".click", ".link", ".download", ".stream",
];

const PHISHING_BRANDS = [
  "paypal", "apple", "amazon", "google", "microsoft", "netflix", "bank",
  "chase", "wellsfargo", "facebook", "instagram", "whatsapp", "dropbox",
  "linkedin", "twitter", "adobe", "docusign", "fedex", "ups", "dhl",
];

function detectInputType(input: string): TrustResult["inputType"] {
  const trimmed = input.trim();
  if (/^https?:\/\//i.test(trimmed) || /^www\./i.test(trimmed) || /^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(\/.*)?$/.test(trimmed)) {
    return "url";
  }
  if (/^[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}$/.test(trimmed)) {
    return "email";
  }
  if (/^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$/.test(trimmed)) {
    return "phone";
  }
  if (trimmed.length > 30) return "message";
  return "unknown";
}

function extractDomain(url: string): string {
  try {
    const withProtocol = url.startsWith("http") ? url : `https://${url}`;
    return new URL(withProtocol).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return url.toLowerCase();
  }
}

function generateFingerprint(input: string): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).padStart(8, "0").toUpperCase();
}

export function analyzeTrust(input: string): TrustResult {
  const startTime = performance.now();
  const signals: TrustSignal[] = [];
  let score = 70;

  const inputType = detectInputType(input);
  const lower = input.toLowerCase();
  const fingerprint = generateFingerprint(input);

  if (inputType === "url" || inputType === "email") {
    const rawDomain = inputType === "url" ? extractDomain(input) : input.split("@")[1] || "";
    const domain = rawDomain.toLowerCase();

    const isTrustedDomain = TRUSTED_DOMAINS.some(td => domain === td || domain.endsWith(`.${td}`));
    if (isTrustedDomain) {
      score += 20;
      signals.push({
        label: "Recognized trusted domain",
        description: `"${domain}" is a well-known, reputable website.`,
        impact: 20,
        category: "technical",
        severity: "positive",
      });
    }

    if (input.includes("@") && !input.startsWith("mailto:") && inputType === "url") {
      score -= 30;
      signals.push({
        label: "@ symbol in URL",
        description: "URLs containing @ are a classic phishing trick — the real destination follows the @.",
        impact: -30,
        category: "url",
        severity: "danger",
      });
    }

    const dotCount = (domain.match(/\./g) || []).length;
    if (dotCount >= 3) {
      score -= 20;
      signals.push({
        label: "Excessive subdomains",
        description: `Domain has ${dotCount} levels — attackers use deep subdomains to obscure the real site.`,
        impact: -20,
        category: "url",
        severity: "warning",
      });
    }

    const isShortener = URL_SHORTENERS.some(s => domain === s || domain.endsWith(`.${s}`));
    if (isShortener) {
      score -= 25;
      signals.push({
        label: "URL shortener detected",
        description: "Short links hide the real destination and are commonly used in phishing attacks.",
        impact: -25,
        category: "url",
        severity: "danger",
      });
    }

    const suspiciousTld = SUSPICIOUS_TLD.find(tld => domain.endsWith(tld));
    if (suspiciousTld) {
      score -= 18;
      signals.push({
        label: `Suspicious top-level domain (${suspiciousTld})`,
        description: `The "${suspiciousTld}" TLD is frequently used in malicious sites due to low cost and minimal verification.`,
        impact: -18,
        category: "technical",
        severity: "warning",
      });
    }

    const hasHTTPS = input.startsWith("https://");
    const hasHTTP = input.startsWith("http://");
    if (hasHTTPS) {
      score += 8;
      signals.push({
        label: "HTTPS encrypted connection",
        description: "The URL uses HTTPS, meaning traffic is encrypted in transit.",
        impact: 8,
        category: "technical",
        severity: "positive",
      });
    } else if (hasHTTP) {
      score -= 15;
      signals.push({
        label: "Unencrypted HTTP connection",
        description: "This URL uses plain HTTP — your data is not encrypted and can be intercepted.",
        impact: -15,
        category: "technical",
        severity: "danger",
      });
    }

    const brandedPhishing = PHISHING_BRANDS.find(brand => {
      const hasBrand = domain.includes(brand);
      const notActual = !TRUSTED_DOMAINS.some(td => domain === td);
      return hasBrand && notActual;
    });
    if (brandedPhishing) {
      score -= 35;
      signals.push({
        label: `Brand impersonation: "${brandedPhishing}"`,
        description: `The domain contains "${brandedPhishing}" but is not the official site — this is a strong indicator of phishing.`,
        impact: -35,
        category: "url",
        severity: "danger",
      });
    }

    const hasNumbers = /\d{4,}/.test(domain.replace(/\./g, ""));
    if (hasNumbers && !isTrustedDomain) {
      score -= 10;
      signals.push({
        label: "Unusual numeric sequences in domain",
        description: "Domains with long number strings are uncommon for legitimate sites.",
        impact: -10,
        category: "url",
        severity: "warning",
      });
    }

    const pathLength = input.replace(/^https?:\/\/[^/]+/, "").length;
    if (pathLength > 200) {
      score -= 12;
      signals.push({
        label: "Excessively long URL path",
        description: "Unusually long URL paths are often used to confuse users about the real destination.",
        impact: -12,
        category: "url",
        severity: "warning",
      });
    }

    if (input.includes("%") || input.includes("..")) {
      score -= 15;
      signals.push({
        label: "URL encoding or path traversal detected",
        description: "Encoded characters or path traversal sequences can be used to bypass security filters.",
        impact: -15,
        category: "url",
        severity: "danger",
      });
    }

    if (/login|signin|account|secure|verify|update|confirm|auth/.test(domain) && !isTrustedDomain) {
      score -= 20;
      signals.push({
        label: "Security keywords in domain name",
        description: `The domain contains words like "login" or "verify" — often used by attackers to appear legitimate.`,
        impact: -20,
        category: "url",
        severity: "danger",
      });
    }
  }

  const spamFound = SPAM_KEYWORDS.filter(kw => lower.includes(kw.toLowerCase()));
  if (spamFound.length > 0) {
    const impact = Math.min(spamFound.length * 8, 45);
    score -= impact;
    signals.push({
      label: `Spam/phishing keywords detected (${spamFound.length})`,
      description: `Found suspicious phrases: "${spamFound.slice(0, 4).join('", "')}"${spamFound.length > 4 ? ` +${spamFound.length - 4} more` : ""}.`,
      impact: -impact,
      category: "content",
      severity: spamFound.length >= 3 ? "danger" : "warning",
    });
  }

  const urgencyWords = ["immediately", "asap", "right now", "don't wait", "expires soon", "last chance", "final notice"];
  const urgencyFound = urgencyWords.filter(w => lower.includes(w));
  if (urgencyFound.length > 0) {
    score -= 15;
    signals.push({
      label: "Artificial urgency language",
      description: "Creating time pressure is a manipulation tactic used to prevent careful thinking.",
      impact: -15,
      category: "content",
      severity: "warning",
    });
  }

  const hasPersonalDataRequest = /\b(ssn|social security|date of birth|dob|mother.s maiden|pin number|cvv|routing number)\b/i.test(input);
  if (hasPersonalDataRequest) {
    score -= 40;
    signals.push({
      label: "Sensitive personal data requested",
      description: "Legitimate services never ask for SSN, CVV, PINs, or similar sensitive data via message/URL.",
      impact: -40,
      category: "content",
      severity: "danger",
    });
  }

  const capsRatio = (input.match(/[A-Z]/g) || []).length / input.length;
  if (capsRatio > 0.4 && input.length > 20) {
    score -= 10;
    signals.push({
      label: "Excessive capitalization",
      description: "Overuse of CAPS is a common tactic to create false urgency or excitement.",
      impact: -10,
      category: "content",
      severity: "warning",
    });
  }

  const excessiveExclamation = (input.match(/!/g) || []).length;
  if (excessiveExclamation >= 3) {
    score -= 8;
    signals.push({
      label: "Multiple exclamation marks",
      description: `${excessiveExclamation} exclamation marks detected — a hallmark of spam and manipulative content.`,
      impact: -8,
      category: "content",
      severity: "warning",
    });
  }

  const hasCurrencyWithClaims = /\$[\d,]+|\d+\s*dollars?|\d+\s*usd/i.test(input) && spamFound.length > 0;
  if (hasCurrencyWithClaims) {
    score -= 15;
    signals.push({
      label: "Monetary claims in suspicious context",
      description: "Specific dollar amounts combined with spam language is a red flag for financial fraud.",
      impact: -15,
      category: "content",
      severity: "danger",
    });
  }

  if (signals.length === 0 && score >= 70) {
    score += 10;
    signals.push({
      label: "No suspicious patterns detected",
      description: "This content passed all automated checks with no red flags found.",
      impact: 10,
      category: "behavior",
      severity: "positive",
    });
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  let riskLevel: TrustResult["riskLevel"];
  let summary: string;
  let recommendation: string;

  if (score >= 70) {
    riskLevel = "Safe";
    summary = "This content appears to be legitimate and safe to interact with.";
    recommendation = "No immediate action required. Always stay vigilant online.";
  } else if (score >= 35) {
    riskLevel = "Suspicious";
    summary = "Several warning signs were detected. Proceed with caution.";
    recommendation = "Do not enter personal information. Verify through official channels before acting.";
  } else {
    riskLevel = "Dangerous";
    summary = "Multiple high-risk indicators detected. This is likely a scam or phishing attempt.";
    recommendation = "Do NOT click any links, share any information, or follow any instructions. Report and delete immediately.";
  }

  const analysisTime = Math.round(performance.now() - startTime);

  return { score, riskLevel, signals, inputType, summary, recommendation, analysisTime, fingerprint };
}
