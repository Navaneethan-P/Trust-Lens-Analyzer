import { useState, useCallback, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { analyzeTrust, TrustResult, TrustSignal } from "@/lib/trustEngine";

const EXAMPLE_INPUTS = [
  { label: "Phishing URL", value: "http://paypal-secure-login.xyz/verify?account=suspended&urgent=true" },
  { label: "Spam message", value: "URGENT! You've WON $1,000,000! Click NOW to claim your FREE prize! Act immediately!" },
  { label: "Safe URL", value: "https://github.com/microsoft/vscode" },
  { label: "Suspicious email", value: "Your account will be SUSPENDED! Verify your bank details immediately at secure-bank-login.top" },
];

function TrustGauge({ score, riskLevel }: { score: number; riskLevel: TrustResult["riskLevel"] }) {
  const color = riskLevel === "Safe" ? "#22c55e" : riskLevel === "Suspicious" ? "#f59e0b" : "#ef4444";
  const glowColor = riskLevel === "Safe" ? "rgba(34,197,94,0.4)" : riskLevel === "Suspicious" ? "rgba(245,158,11,0.4)" : "rgba(239,68,68,0.4)";
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="gauge-container">
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r="54" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="12" />
        <motion.circle
          cx="70" cy="70" r="54"
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1.2, ease: "easeOut" }}
          style={{ transformOrigin: "70px 70px", rotate: "-90deg", filter: `drop-shadow(0 0 8px ${glowColor})` }}
        />
        <motion.text
          x="70" y="66"
          textAnchor="middle"
          fill={color}
          fontSize="26"
          fontWeight="800"
          fontFamily="Inter, sans-serif"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5, duration: 0.5 }}
        >
          {score}
        </motion.text>
        <text x="70" y="84" textAnchor="middle" fill="rgba(255,255,255,0.5)" fontSize="11" fontFamily="Inter, sans-serif">
          / 100
        </text>
      </svg>
    </div>
  );
}

function RiskBadge({ level }: { level: TrustResult["riskLevel"] }) {
  const cfg = {
    Safe: { bg: "rgba(34,197,94,0.15)", border: "rgba(34,197,94,0.4)", text: "#22c55e", icon: "✓" },
    Suspicious: { bg: "rgba(245,158,11,0.15)", border: "rgba(245,158,11,0.4)", text: "#f59e0b", icon: "⚠" },
    Dangerous: { bg: "rgba(239,68,68,0.15)", border: "rgba(239,68,68,0.4)", text: "#ef4444", icon: "✕" },
  }[level];

  return (
    <motion.div
      className="risk-badge"
      style={{ background: cfg.bg, border: `1px solid ${cfg.border}`, color: cfg.text }}
      initial={{ scale: 0.8, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ delay: 0.3, type: "spring", stiffness: 300 }}
    >
      <span className="risk-icon">{cfg.icon}</span>
      <span className="risk-label">{level}</span>
    </motion.div>
  );
}

function SignalCard({ signal, index }: { signal: TrustSignal; index: number }) {
  const cfg = {
    positive: { border: "rgba(34,197,94,0.3)", bg: "rgba(34,197,94,0.07)", color: "#22c55e", dot: "#22c55e" },
    warning: { border: "rgba(245,158,11,0.3)", bg: "rgba(245,158,11,0.07)", color: "#f59e0b", dot: "#f59e0b" },
    danger: { border: "rgba(239,68,68,0.3)", bg: "rgba(239,68,68,0.07)", color: "#ef4444", dot: "#ef4444" },
  }[signal.severity];

  const categoryIcons = {
    url: "🔗",
    content: "📝",
    behavior: "🔍",
    technical: "⚙️",
  };

  return (
    <motion.div
      className="signal-card"
      style={{ borderColor: cfg.border, background: cfg.bg }}
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: 0.1 + index * 0.07, duration: 0.4 }}
    >
      <div className="signal-header">
        <span className="signal-dot" style={{ background: cfg.dot }} />
        <span className="signal-category">{categoryIcons[signal.category]}</span>
        <span className="signal-label" style={{ color: cfg.color }}>{signal.label}</span>
        <span className="signal-impact" style={{ color: signal.impact > 0 ? "#22c55e" : "#ef4444" }}>
          {signal.impact > 0 ? `+${signal.impact}` : signal.impact}
        </span>
      </div>
      <p className="signal-description">{signal.description}</p>
    </motion.div>
  );
}

function ScoreBar({ score, riskLevel }: { score: number; riskLevel: TrustResult["riskLevel"] }) {
  const color = riskLevel === "Safe" ? "#22c55e" : riskLevel === "Suspicious" ? "#f59e0b" : "#ef4444";
  return (
    <div className="score-bar-container">
      <div className="score-bar-track">
        <motion.div
          className="score-bar-fill"
          style={{ background: `linear-gradient(90deg, ${color}88, ${color})` }}
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 1.2, ease: "easeOut" }}
        />
      </div>
      <div className="score-bar-labels">
        <span style={{ color: "#ef4444" }}>Dangerous</span>
        <span style={{ color: "#f59e0b" }}>Suspicious</span>
        <span style={{ color: "#22c55e" }}>Safe</span>
      </div>
      <div className="score-bar-markers">
        <div className="marker" style={{ left: "35%" }} />
        <div className="marker" style={{ left: "70%" }} />
      </div>
    </div>
  );
}

function AnalysisStats({ result }: { result: TrustResult }) {
  const positiveCount = result.signals.filter(s => s.severity === "positive").length;
  const warningCount = result.signals.filter(s => s.severity === "warning").length;
  const dangerCount = result.signals.filter(s => s.severity === "danger").length;

  return (
    <div className="stats-row">
      {[
        { label: "Signals Found", value: result.signals.length, color: "#a78bfa" },
        { label: "Pass", value: positiveCount, color: "#22c55e" },
        { label: "Warnings", value: warningCount, color: "#f59e0b" },
        { label: "Threats", value: dangerCount, color: "#ef4444" },
        { label: "Analysis", value: `${result.analysisTime}ms`, color: "#60a5fa" },
        { label: "Input Type", value: result.inputType.toUpperCase(), color: "#94a3b8" },
      ].map((stat, i) => (
        <motion.div
          key={stat.label}
          className="stat-card"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 + i * 0.06 }}
        >
          <span className="stat-value" style={{ color: stat.color }}>{stat.value}</span>
          <span className="stat-label">{stat.label}</span>
        </motion.div>
      ))}
    </div>
  );
}

function PulsingDot() {
  return (
    <span className="pulsing-dot-wrapper">
      <span className="pulsing-dot" />
    </span>
  );
}

export default function TrustAnalyzer() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<TrustResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [history, setHistory] = useState<Array<{ input: string; result: TrustResult }>>([]);
  const [showHistory, setShowHistory] = useState(false);
  const resultRef = useRef<HTMLDivElement>(null);

  const handleAnalyze = useCallback(() => {
    if (!input.trim()) return;
    setIsAnalyzing(true);
    setResult(null);

    setTimeout(() => {
      const res = analyzeTrust(input.trim());
      setResult(res);
      setHistory(prev => [{ input: input.trim(), result: res }, ...prev].slice(0, 10));
      setIsAnalyzing(false);
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 100);
    }, 900 + Math.random() * 400);
  }, [input]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) handleAnalyze();
  };

  const handleExample = (value: string) => {
    setInput(value);
    setResult(null);
  };

  return (
    <div className="app-bg">
      <div className="noise-overlay" />

      <div className="top-bar">
        <div className="logo-mark">
          <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
            <circle cx="14" cy="14" r="13" stroke="url(#grad)" strokeWidth="2"/>
            <path d="M14 7L14 14L19 17" stroke="url(#grad)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            <defs>
              <linearGradient id="grad" x1="0" y1="0" x2="28" y2="28" gradientUnits="userSpaceOnUse">
                <stop stopColor="#a78bfa"/>
                <stop offset="1" stopColor="#60a5fa"/>
              </linearGradient>
            </defs>
          </svg>
          <span className="logo-text">TrustLens <span className="logo-ai">AI</span></span>
        </div>
        <div className="top-bar-right">
          <div className="live-indicator">
            <PulsingDot /> Live Analysis
          </div>
          {history.length > 0 && (
            <button className="history-btn" onClick={() => setShowHistory(!showHistory)}>
              {showHistory ? "Hide" : "History"} ({history.length})
            </button>
          )}
        </div>
      </div>

      <main className="main-content">
        <motion.div
          className="hero-section"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <div className="hero-badge">
            <span className="hero-badge-dot" />
            AI-Powered Digital Trust Analysis
          </div>
          <h1 className="hero-title">
            Is this <span className="gradient-text">safe</span> or a<br />
            <span className="gradient-text-danger">threat</span>?
          </h1>
          <p className="hero-subtitle">
            Paste any URL, message, or email to instantly detect phishing, scams,<br />
            and suspicious content with multi-signal AI analysis.
          </p>
        </motion.div>

        <motion.div
          className="input-card"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2, duration: 0.5 }}
        >
          <div className="input-label">
            <span className="input-label-dot" />
            Paste URL, message, email, or any suspicious content
          </div>
          <textarea
            className="trust-input"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="e.g. https://suspicious-site.xyz/login or 'You won a prize! Click now to claim...'"
            rows={4}
          />

          <div className="input-footer">
            <div className="examples-row">
              <span className="examples-label">Try examples:</span>
              {EXAMPLE_INPUTS.map(ex => (
                <button key={ex.label} className="example-chip" onClick={() => handleExample(ex.value)}>
                  {ex.label}
                </button>
              ))}
            </div>
            <button
              className={`analyze-btn ${isAnalyzing ? "analyzing" : ""} ${!input.trim() ? "disabled" : ""}`}
              onClick={handleAnalyze}
              disabled={isAnalyzing || !input.trim()}
            >
              {isAnalyzing ? (
                <>
                  <span className="spinner" />
                  Analyzing...
                </>
              ) : (
                <>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="11" cy="11" r="8"/>
                    <path d="m21 21-4.35-4.35"/>
                  </svg>
                  Analyze Trust
                </>
              )}
            </button>
          </div>
        </motion.div>

        <AnimatePresence>
          {isAnalyzing && (
            <motion.div
              className="scanning-indicator"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
            >
              <div className="scan-bar">
                <motion.div
                  className="scan-progress"
                  initial={{ width: "0%" }}
                  animate={{ width: "100%" }}
                  transition={{ duration: 1.2, ease: "linear" }}
                />
              </div>
              <div className="scan-steps">
                {["Parsing structure...", "Checking domain reputation...", "Analyzing content...", "Calculating trust score..."].map((step, i) => (
                  <motion.span
                    key={step}
                    className="scan-step"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: i * 0.2 }}
                  >
                    {step}
                  </motion.span>
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        <AnimatePresence>
          {result && (
            <motion.div
              ref={resultRef}
              className="result-section"
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.5 }}
            >
              <div className="result-main-card">
                <div className="result-score-area">
                  <TrustGauge score={result.score} riskLevel={result.riskLevel} />
                  <div className="result-score-info">
                    <div className="result-score-number" style={{
                      color: result.riskLevel === "Safe" ? "#22c55e" : result.riskLevel === "Suspicious" ? "#f59e0b" : "#ef4444"
                    }}>
                      Trust Score
                    </div>
                    <RiskBadge level={result.riskLevel} />
                    <div className="fingerprint-badge">
                      ID: {result.fingerprint}
                    </div>
                  </div>
                </div>

                <ScoreBar score={result.score} riskLevel={result.riskLevel} />

                <div className="result-summary-box" style={{
                  borderColor: result.riskLevel === "Safe" ? "rgba(34,197,94,0.3)" : result.riskLevel === "Suspicious" ? "rgba(245,158,11,0.3)" : "rgba(239,68,68,0.3)",
                  background: result.riskLevel === "Safe" ? "rgba(34,197,94,0.05)" : result.riskLevel === "Suspicious" ? "rgba(245,158,11,0.05)" : "rgba(239,68,68,0.05)",
                }}>
                  <p className="result-summary">{result.summary}</p>
                </div>

                <div className="recommendation-box">
                  <span className="rec-icon">
                    {result.riskLevel === "Safe" ? "✓" : result.riskLevel === "Suspicious" ? "⚠" : "⛔"}
                  </span>
                  <p className="rec-text">{result.recommendation}</p>
                </div>
              </div>

              <AnalysisStats result={result} />

              <div className="signals-section">
                <h3 className="signals-title">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{display:"inline",marginRight:8}}>
                    <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                  </svg>
                  Detection Signals ({result.signals.length})
                </h3>
                <div className="signals-grid">
                  {result.signals.map((signal, i) => (
                    <SignalCard key={i} signal={signal} index={i} />
                  ))}
                </div>
              </div>

              <div className="disclaimer">
                Analysis completed in {result.analysisTime}ms · Fingerprint {result.fingerprint} · TrustLens AI uses pattern analysis — always verify with official sources.
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        <AnimatePresence>
          {showHistory && history.length > 0 && (
            <motion.div
              className="history-panel"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 20 }}
            >
              <h3 className="history-title">Recent Analyses</h3>
              <div className="history-list">
                {history.map((item, i) => {
                  const color = item.result.riskLevel === "Safe" ? "#22c55e" : item.result.riskLevel === "Suspicious" ? "#f59e0b" : "#ef4444";
                  return (
                    <button
                      key={i}
                      className="history-item"
                      onClick={() => { setInput(item.input); setResult(item.result); setShowHistory(false); }}
                    >
                      <span className="history-score" style={{ color }}>{item.result.score}</span>
                      <span className="history-risk" style={{ color }}>{item.result.riskLevel}</span>
                      <span className="history-input">{item.input.slice(0, 60)}{item.input.length > 60 ? "..." : ""}</span>
                    </button>
                  );
                })}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      <footer className="footer">
        <p>TrustLens AI · Digital Trust Analyzer · Built for security awareness</p>
        <p className="footer-sub">All analysis is performed locally in your browser. No data is sent to any server.</p>
      </footer>
    </div>
  );
}
