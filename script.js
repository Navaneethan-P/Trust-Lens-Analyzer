// TrustLens - Production Quality Threat Analysis Engine
document.addEventListener('DOMContentLoaded', function() {
    // ===================== DOM ELEMENTS =====================
    const analyzeBtn = document.getElementById('analyzeBtn');
    const trustInput = document.getElementById('trustInput');
    const resultsSection = document.getElementById('resultsSection');
    const scoreValue = document.getElementById('scoreValue');
    const scoreProgress = document.getElementById('scoreProgress');
    const riskLevel = document.getElementById('riskLevel');
    const explanationText = document.getElementById('explanationText');
    const insightLine = document.getElementById('insightLine');
    const safetyTip = document.getElementById('safetyTip');
    const charCount = document.getElementById('charCount');
    const copyBtn = document.getElementById('copyBtn');
    const clearBtn = document.getElementById('clearBtn');
    const historySection = document.getElementById('historySection');
    const historyList = document.getElementById('historyList');
    const contentRiskBar = document.getElementById('contentRiskBar');
    const linkRiskBar = document.getElementById('linkRiskBar');
    const intentRiskBar = document.getElementById('intentRiskBar');
    const tacticsList = document.getElementById('tacticsList');
    const demoBtn = document.getElementById('demoBtn');

    // ===================== APP STATE =====================
    let lastAnalysisResult = null;
    let analysisHistory = JSON.parse(localStorage.getItem('trustLensHistory')) || [];

    // ===================== EVENT LISTENERS =====================
    analyzeBtn.addEventListener('click', handleAnalyze);
    clearBtn.addEventListener('click', handleClear);
    copyBtn.addEventListener('click', handleCopy);
    
    trustInput.addEventListener('input', updateCharCount);
    trustInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && e.ctrlKey) handleAnalyze();
    });

    if (demoBtn) {
        demoBtn.addEventListener('click', function() {
            trustInput.value = 'URGENT: Verify your account immediately. Click here: http://192.168.1.1/verify?token=abc123 LIMITED TIME OFFER!';
            updateCharCount();
            handleAnalyze();
        });
    }

    // ===================== HANDLERS =====================
    function handleAnalyze() {
        const input = trustInput.value.trim();
        if (!input.length) {
            showAlert('Please enter content to analyze');
            return;
        }

        const analysis = analyzeContent(input);
        visualizeResults(analysis);
        lastAnalysisResult = analysis;
        saveToHistory(analysis);
        updateHistoryDisplay();
    }

    function handleClear() {
        trustInput.value = '';
        resultsSection.classList.add('hidden');
        lastAnalysisResult = null;
        updateCharCount();
    }

    function handleCopy() {
        if (!lastAnalysisResult) return;
        
        const report = formatReport(lastAnalysisResult);
        navigator.clipboard.writeText(report).then(() => {
            copyBtn.textContent = '✅ Copied!';
            setTimeout(() => { copyBtn.textContent = '📋 Copy Report'; }, 2000);
        }).catch(() => {
            copyBtn.textContent = '❌ Error!';
            setTimeout(() => { copyBtn.textContent = '📋 Copy Report'; }, 2000);
        });
    }

    function updateCharCount() {
        const len = trustInput.value.length;
        charCount.textContent = `${len}/500`;
        if (len > 450) charCount.style.color = '#ff3860';
        else charCount.style.color = '#3d85ff';
    }

    // ===================== THREAT ANALYSIS ENGINE =====================
    function analyzeContent(input) {
        const lower = input.toLowerCase();
        
        // Calculate individual risk scores
        const urgencyRisk = calculateUrgencyRisk(lower);
        const rewardRisk = calculateRewardRisk(lower);
        const actionRisk = calculateActionRisk(lower);
        const urlRisk = calculateUrlRisk(input);
        const pressureRisk = calculatePressureRisk(lower);
        const emotionalRisk = calculateEmotionalRisk(lower);
        const impersonationRisk = calculateImpersonationRisk(lower);
        const infoRequestRisk = calculateInfoRequestRisk(lower);

        // Weighted scoring
        const totalRisk = (
            urgencyRisk * 0.15 +
            rewardRisk * 0.14 +
            actionRisk * 0.12 +
            urlRisk * 0.20 +
            pressureRisk * 0.10 +
            emotionalRisk * 0.08 +
            impersonationRisk * 0.12 +
            infoRequestRisk * 0.09
        );

        const trustScore = Math.max(0, Math.min(100, 100 - totalRisk));
        const riskLevel = determineThreatLevel(trustScore);
        const tactics = detectTactics(lower, input);
        
        // Calculate dimensional breakdown
        const contentRisk = Math.min(100, urgencyRisk * 0.25 + rewardRisk * 0.25 + pressureRisk * 0.2 + emotionalRisk * 0.15 + infoRequestRisk * 0.15);
        const linkRisk = calculateDimensionalLinkRisk(input);
        const intentRisk = Math.min(100, actionRisk * 0.4 + rewardRisk * 0.25 + infoRequestRisk * 0.35);

        return {
            input,
            trustScore: Math.round(trustScore),
            riskLevel,
            tactics,
            breakdown: {
                content: Math.round(contentRisk),
                link: Math.round(linkRisk),
                intent: Math.round(intentRisk)
            },
            explanation: generateExplanation(lower, input, tactics),
            recommendation: getRecommendation(riskLevel),
            timestamp: new Date().toLocaleTimeString()
        };
    }

    // ===== Risk Calculation Functions =====
    function calculateUrgencyRisk(lower) {
        const patterns = ['urgent', 'immediately', 'asap', 'hurry', 'quickly', 'now', 'act now', 'don\'t wait', 'deadline', 'expires', 'limited time', 'time-sensitive'];
        const count = patterns.filter(p => lower.includes(p)).length;
        return Math.min(100, count * 15);
    }

    function calculateRewardRisk(lower) {
        const patterns = ['win', 'won', 'prize', 'reward', 'free', 'claim', 'congratulations', 'selected', 'gift', 'bonus', 'money', 'cash'];
        const count = patterns.filter(p => lower.includes(p)).length;
        return Math.min(100, count * 12);
    }

    function calculateActionRisk(lower) {
        const patterns = ['click', 'tap', 'verify', 'confirm', 'authenticate', 'update', 'validate', 'reactivate', 'download', 'install'];
        const count = patterns.filter(p => lower.includes(p)).length;
        return Math.min(100, count * 10);
    }

    function calculateUrlRisk(input) {
        let risk = 0;
        if (input.includes('@')) risk += 30; // Email spoofing
        if (/bit\.ly|t\.co|goo\.gl|tinyurl|ow\.ly|short\.link|is\.gd/.test(input)) risk += 25; // URL shorteners
        if (input.includes('..') || input.includes('../')) risk += 20; // Path traversal
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(input)) risk += 15; // IP address
        if ((input.match(/\./g) || []).length > 5) risk += 10; // Excessive subdomains
        if (input.toLowerCase().includes('http://')) risk += 5; // Unencrypted
        return Math.min(100, risk);
    }

    function calculateDimensionalLinkRisk(input) {
        let risk = 0;
        if (input.includes('@')) risk += 35;
        if (/bit\.ly|t\.co|goo\.gl|tinyurl|ow\.ly/.test(input)) risk += 30;
        if (input.includes('..') || input.includes('../')) risk += 25;
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(input)) risk += 20;
        if ((input.match(/\./g) || []).length > 5) risk += 15;
        return Math.min(100, risk);
    }

    function calculatePressureRisk(lower) {
        const patterns = ['limited', 'exclusive', 'rare', 'last chance', 'only few', 'restricted', 'members only', 'invitation only'];
        const count = patterns.filter(p => lower.includes(p)).length;
        return Math.min(100, count * 10);
    }

    function calculateEmotionalRisk(lower) {
        const patterns = ['alert', 'warning', 'danger', 'breach', 'fraud', 'locked', 'suspended', 'compromised', 'attack', 'concerned'];
        const count = patterns.filter(p => lower.includes(p)).length;
        return Math.min(100, count * 8);
    }

    function calculateImpersonationRisk(lower) {
        const brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'bank', 'irs', 'fbi', 'government', 'revenue'];
        const count = brands.filter(b => lower.includes(b)).length;
        return Math.min(100, count > 1 ? count * 12 : 0);
    }

    function calculateInfoRequestRisk(lower) {
        const patterns = ['password', 'pin', 'ssn', 'credit card', 'banking', 'social security', 'account number', 'routing'];
        const count = patterns.filter(p => lower.includes(p)).length;
        return Math.min(100, count * 15);
    }

    function determineThreatLevel(score) {
        if (score > 75) return 'Safe';
        if (score > 45) return 'Suspicious';
        return 'Dangerous';
    }

    function detectTactics(lower, input) {
        const tactics = [];
        if (lower.includes('urgent') || lower.includes('immediately')) tactics.push('Urgency Pressure');
        if (lower.includes('limited') || lower.includes('exclusive')) tactics.push('Scarcity Manipulation');
        if (lower.includes('win') || lower.includes('free') || lower.includes('prize')) tactics.push('Reward Bait');
        if (lower.includes('click') || lower.includes('verify') || lower.includes('confirm')) tactics.push('Forced Action');
        if (lower.includes('alert') || lower.includes('warning') || lower.includes('breach')) tactics.push('Fear Exploitation');
        if (lower.includes('congratulations') || lower.includes('selected')) tactics.push('False Validation');
        if (lower.includes('password') || lower.includes('pin')) tactics.push('Credential Harvesting');
        if (input.includes('@')) tactics.push('Domain Spoofing');
        if (/bit\.ly|t\.co|goo\.gl|tinyurl|ow\.ly/.test(input)) tactics.push('URL Masking');
        if (lower.includes('update') || lower.includes('reactivate')) tactics.push('Account Hijacking');
        return [...new Set(tactics)];
    }

    function generateExplanation(lower, input, tactics) {
        const reasons = [];
        
        if (lower.includes('urgent') || lower.includes('immediately')) {
            reasons.push('⚠️ Creates artificial urgency to bypass rational thought');
        }
        if (lower.includes('win') || lower.includes('prize')) {
            reasons.push('💰 Promises unrealistic gains - classic financial scam indicator');
        }
        if (lower.includes('click') || lower.includes('verify')) {
            reasons.push('🔗 Requests immediate action on unverified links');
        }
        if (input.includes('@')) {
            reasons.push('🚨 URL structure indicates domain spoofing attempt');
        }
        if (/bit\.ly|t\.co|goo\.gl|tinyurl/.test(input)) {
            reasons.push('🔐 URL shortener masks actual destination');
        }
        if (lower.includes('password') || lower.includes('credit card')) {
            reasons.push('💳 Direct request for sensitive personal/financial data');
        }
        if (lower.includes('alert') || lower.includes('breach')) {
            reasons.push('😨 Emotional manipulation using fake security alerts');
        }
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(input)) {
            reasons.push('🚨 IP address used instead of legitimate domain');
        }

        return reasons.length > 0 
            ? reasons.join(' ') 
            : '✅ No major risk patterns detected - appears legitimate.';
    }

    function getRecommendation(level) {
        const recommendations = {
            'Safe': '✓ Appears legitimate. Standard caution recommended.',
            'Suspicious': '⚠️ Multiple warning signs. Do not click links or share information.',
            'Dangerous': '🚨 High confidence threat. Delete immediately and report if phishing.'
        };
        return recommendations[level] || 'Always verify independently.';
    }

    // ===================== VISUALIZATION =====================
    function visualizeResults(analysis) {
        resultsSection.classList.remove('hidden');
        resultsSection.classList.remove('safe', 'suspicious', 'dangerous');
        resultsSection.classList.add(analysis.riskLevel.toLowerCase());

        // Animate score
        animateScore(analysis.trustScore);

        // Update bars
        animateBar(contentRiskBar, analysis.breakdown.content);
        animateBar(linkRiskBar, analysis.breakdown.link);
        animateBar(intentRiskBar, analysis.breakdown.intent);

        // Update tactics
        tacticsList.innerHTML = '';
        if (analysis.tactics.length === 0) {
            tacticsList.innerHTML = '<span class="no-tags">None Detected</span>';
        } else {
            analysis.tactics.forEach(t => {
                const tag = document.createElement('span');
                tag.className = 'tactic-tag';
                tag.textContent = t;
                tacticsList.appendChild(tag);
            });
        }

        // Update text
        riskLevel.textContent = analysis.riskLevel;
        explanationText.textContent = analysis.explanation;
        insightLine.textContent = generateInsight(analysis);
        insightLine.classList.remove('hidden');
        safetyTip.textContent = analysis.recommendation;
    }

    function animateScore(targetScore) {
        const duration = 1000;
        const start = performance.now();
        const radius = 45;
        const circumference = 2 * Math.PI * radius;
        scoreProgress.style.strokeDasharray = circumference;

        const animate = (now) => {
            const elapsed = now - start;
            const progress = Math.min(elapsed / duration, 1);
            const eased = progress < 0.5 ? 4 * progress ** 3 : 1 - (-2 * progress + 2) ** 3 / 2;
            
            scoreValue.textContent = Math.round(eased * targetScore);
            scoreProgress.style.strokeDashoffset = circumference - (eased * targetScore / 100) * circumference;
            
            if (progress < 1) requestAnimationFrame(animate);
        };
        requestAnimationFrame(animate);
    }

    function animateBar(element, targetWidth) {
        element.style.width = '0%';
        setTimeout(() => {
            element.style.width = Math.min(targetWidth, 100) + '%';
        }, 50);
    }

    function generateInsight(analysis) {
        const { trustScore, tactics } = analysis;
        if (trustScore >= 80) return '✅ This appears to be legitimate communication.';
        if (trustScore >= 60) return '⚠️ Multiple risk factors detected - verify sender independently.';
        return '🚨 HIGH THREAT - Multiple scam indicators. Delete immediately.';
    }

    // ===================== HISTORY MANAGEMENT =====================
    function saveToHistory(analysis) {
        const entry = {
            text: analysis.input.substring(0, 40) + (analysis.input.length > 40 ? '...' : ''),
            score: analysis.trustScore,
            level: analysis.riskLevel,
            time: analysis.timestamp
        };
        
        analysisHistory.unshift(entry);
        if (analysisHistory.length > 15) analysisHistory.pop();
        localStorage.setItem('trustLensHistory', JSON.stringify(analysisHistory));
    }

    function updateHistoryDisplay() {
        if (analysisHistory.length === 0) {
            historySection.classList.add('hidden');
            return;
        }

        historySection.classList.remove('hidden');
        historyList.innerHTML = '';

        analysisHistory.slice(0, 8).forEach(item => {
            const div = document.createElement('div');
            div.className = 'history-item';
            div.innerHTML = `<span>${item.text}</span><span>${item.score} - ${item.level}</span>`;
            div.addEventListener('click', () => {
                trustInput.value = item.text;
                updateCharCount();
                handleAnalyze();
            });
            historyList.appendChild(div);
        });
    }

    function formatReport(analysis) {
        return `TRUSTLENS THREAT ANALYSIS REPORT
================================
Scan Time: ${analysis.timestamp}
Trust Score: ${analysis.trustScore}/100
Threat Level: ${analysis.riskLevel}

ANALYZED CONTENT:
${analysis.input}

THREAT BREAKDOWN:
• Content Risk: ${analysis.breakdown.content}%
• Link Risk: ${analysis.breakdown.link}%
• Intent Risk: ${analysis.breakdown.intent}%

DETECTED TACTICS (${analysis.tactics.length}):
${analysis.tactics.length > 0 ? analysis.tactics.map(t => `  • ${t}`).join('\n') : '  None detected'}

ANALYSIS:
${analysis.explanation}

RECOMMENDATION:
${analysis.recommendation}

---
Powered by TrustLens Security Engine`;
    }

    function showAlert(message) {
        alert(message);
    }

    // ===================== INITIALIZATION =====================
    updateHistoryDisplay();
    console.log('✅ TrustLens Engine Initialized');
});
// TrustLens - Production Quality Threat Analysis Engine
document.addEventListener('DOMContentLoaded', function() {
    // ===================== DOM ELEMENTS =====================
    const analyzeBtn = document.getElementById('analyzeBtn');
    const trustInput = document.getElementById('trustInput');
    const resultsSection = document.getElementById('resultsSection');
    const scoreValue = document.getElementById('scoreValue');
    const scoreProgress = document.getElementById('scoreProgress');
    const riskLevel = document.getElementById('riskLevel');
    const explanationText = document.getElementById('explanationText');
    const insightLine = document.getElementById('insightLine');
    const safetyTip = document.getElementById('safetyTip');
    const charCount = document.getElementById('charCount');
    const copyBtn = document.getElementById('copyBtn');
    const clearBtn = document.getElementById('clearBtn');
    const historySection = document.getElementById('historySection');
    const historyList = document.getElementById('historyList');
    const contentRiskBar = document.getElementById('contentRiskBar');
    const linkRiskBar = document.getElementById('linkRiskBar');
    const intentRiskBar = document.getElementById('intentRiskBar');
    const tacticsList = document.getElementById('tacticsList');
    const demoBtn = document.getElementById('demoBtn');

    // ===================== APP STATE =====================
    let lastAnalysisResult = null;
    let analysisHistory = JSON.parse(localStorage.getItem('trustLensHistory')) || [];

    // ===================== EVENT LISTENERS =====================
    analyzeBtn.addEventListener('click', handleAnalyze);
    clearBtn.addEventListener('click', handleClear);
    copyBtn.addEventListener('click', handleCopy);
    
    trustInput.addEventListener('input', updateCharCount);
    trustInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && e.ctrlKey) handleAnalyze();
    });

    if (demoBtn) {
        demoBtn.addEventListener('click', function() {
            trustInput.value = 'URGENT: Verify your account immediately. Click here: http://192.168.1.1/verify?token=abc123 LIMITED TIME OFFER!';
            updateCharCount();
            handleAnalyze();
        });
    }

    // ===================== HANDLERS =====================
    function handleAnalyze() {
        const input = trustInput.value.trim();
        if (!input.length) {
            showAlert('Please enter content to analyze');
            return;
        }

        const analysis = analyzeContent(input);
        visualizeResults(analysis);
        lastAnalysisResult = analysis;
        saveToHistory(analysis);
        updateHistoryDisplay();
    }

    function handleClear() {
        trustInput.value = '';
        resultsSection.classList.add('hidden');
        lastAnalysisResult = null;
        updateCharCount();
    }

    function handleCopy() {
        if (!lastAnalysisResult) return;
        
        const report = formatReport(lastAnalysisResult);
        navigator.clipboard.writeText(report).then(() => {
            copyBtn.textContent = '✅ Copied!';
            setTimeout(() => { copyBtn.textContent = '📋 Copy Report'; }, 2000);
        }).catch(() => {
            copyBtn.textContent = '❌ Error!';
            setTimeout(() => { copyBtn.textContent = '📋 Copy Report'; }, 2000);
        });
    }

    function updateCharCount() {
        const len = trustInput.value.length;
        charCount.textContent = `${len}/500`;
        if (len > 450) charCount.style.color = '#ff3860';
        else charCount.style.color = '#3d85ff';
    }

    // ===================== THREAT ANALYSIS ENGINE =====================
    function analyzeContent(input) {
        const lower = input.toLowerCase();
        
        // Calculate individual risk scores
        const urgencyRisk = calculateUrgencyRisk(lower);
        const rewardRisk = calculateRewardRisk(lower);
        const actionRisk = calculateActionRisk(lower);
        const urlRisk = calculateUrlRisk(input);
        const pressureRisk = calculatePressureRisk(lower);
        const emotionalRisk = calculateEmotionalRisk(lower);
        const impersonationRisk = calculateImpersonationRisk(lower);
        const infoRequestRisk = calculateInfoRequestRisk(lower);

        // Weighted scoring
        const totalRisk = (
            urgencyRisk * 0.15 +
            rewardRisk * 0.14 +
            actionRisk * 0.12 +
            urlRisk * 0.20 +
            pressureRisk * 0.10 +
            emotionalRisk * 0.08 +
            impersonationRisk * 0.12 +
            infoRequestRisk * 0.09
        );

        const trustScore = Math.max(0, Math.min(100, 100 - totalRisk));
        const riskLevel = determineThreatLevel(trustScore);
        const tactics = detectTactics(lower, input);
        
        // Calculate dimensional breakdown
        const contentRisk = Math.min(100, urgencyRisk * 0.25 + rewardRisk * 0.25 + pressureRisk * 0.2 + emotionalRisk * 0.15 + infoRequestRisk * 0.15);
        const linkRisk = calculateDimensionalLinkRisk(input);
        const intentRisk = Math.min(100, actionRisk * 0.4 + rewardRisk * 0.25 + infoRequestRisk * 0.35);

        return {
            input,
            trustScore: Math.round(trustScore),
            riskLevel,
            tactics,
            breakdown: {
                content: Math.round(contentRisk),
                link: Math.round(linkRisk),
                intent: Math.round(intentRisk)
            },
            explanation: generateExplanation(lower, input, tactics),
            recommendation: getRecommendation(riskLevel),
            timestamp: new Date().toLocaleTimeString()
        };
    }

    // ===== Risk Calculation Functions =====
    function calculateUrgencyRisk(lower) {
        const patterns = ['urgent', 'immediately', 'asap', 'hurry', 'quickly', 'now', 'act now', 'don\'t wait', 'deadline', 'expires', 'limited time', 'time-sensitive'];
        const count = patterns.filter(p => lower.includes(p)).length;
        return Math.min(100, count * 15);
    }

    function calculateRewardRisk(lower) {
        const patterns = ['win', 'won', 'prize', 'reward', 'free', 'claim', 'congratulations', 'selected', 'gift', 'bonus', 'money', 'cash'];
        const count = patterns.filter(p => lower.includes(p)).length;
        return Math.min(100, count * 12);
    }

    function calculateActionRisk(lower) {
        const patterns = ['click', 'tap', 'verify', 'confirm', 'authenticate', 'update', 'validate', 'reactivate', 'download', 'install'];
        const count = patterns.filter(p => lower.includes(p)).length;
        return Math.min(100, count * 10);
    }

    function calculateUrlRisk(input) {
        let risk = 0;
        if (input.includes('@')) risk += 30; // Email spoofing
        if (/bit\.ly|t\.co|goo\.gl|tinyurl|ow\.ly|short\.link|is\.gd/.test(input)) risk += 25; // URL shorteners
        if (input.includes('..') || input.includes('../')) risk += 20; // Path traversal
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(input)) risk += 15; // IP address
        if ((input.match(/\./g) || []).length > 5) risk += 10; // Excessive subdomains
        if (input.toLowerCase().includes('http://')) risk += 5; // Unencrypted
        return Math.min(100, risk);
    }

    function calculateDimensionalLinkRisk(input) {
        let risk = 0;
        if (input.includes('@')) risk += 35;
        if (/bit\.ly|t\.co|goo\.gl|tinyurl|ow\.ly/.test(input)) risk += 30;
        if (input.includes('..') || input.includes('../')) risk += 25;
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(input)) risk += 20;
        if ((input.match(/\./g) || []).length > 5) risk += 15;
        return Math.min(100, risk);
    }

    function calculatePressureRisk(lower) {
        const patterns = ['limited', 'exclusive', 'rare', 'last chance', 'only few', 'restricted', 'members only', 'invitation only'];
        const count = patterns.filter(p => lower.includes(p)).length;
        return Math.min(100, count * 10);
    }

    function calculateEmotionalRisk(lower) {
        const patterns = ['alert', 'warning', 'danger', 'breach', 'fraud', 'locked', 'suspended', 'compromised', 'attack', 'concerned'];
        const count = patterns.filter(p => lower.includes(p)).length;
        return Math.min(100, count * 8);
    }

    function calculateImpersonationRisk(lower) {
        const brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'bank', 'irs', 'fbi', 'government', 'revenue'];
        const count = brands.filter(b => lower.includes(b)).length;
        return Math.min(100, count > 1 ? count * 12 : 0);
    }

    function calculateInfoRequestRisk(lower) {
        const patterns = ['password', 'pin', 'ssn', 'credit card', 'banking', 'social security', 'account number', 'routing'];
        const count = patterns.filter(p => lower.includes(p)).length;
        return Math.min(100, count * 15);
    }

    function determineThreatLevel(score) {
        if (score > 75) return 'Safe';
        if (score > 45) return 'Suspicious';
        return 'Dangerous';
    }

    function detectTactics(lower, input) {
        const tactics = [];
        if (lower.includes('urgent') || lower.includes('immediately')) tactics.push('Urgency Pressure');
        if (lower.includes('limited') || lower.includes('exclusive')) tactics.push('Scarcity Manipulation');
        if (lower.includes('win') || lower.includes('free') || lower.includes('prize')) tactics.push('Reward Bait');
        if (lower.includes('click') || lower.includes('verify') || lower.includes('confirm')) tactics.push('Forced Action');
        if (lower.includes('alert') || lower.includes('warning') || lower.includes('breach')) tactics.push('Fear Exploitation');
        if (lower.includes('congratulations') || lower.includes('selected')) tactics.push('False Validation');
        if (lower.includes('password') || lower.includes('pin')) tactics.push('Credential Harvesting');
        if (input.includes('@')) tactics.push('Domain Spoofing');
        if (/bit\.ly|t\.co|goo\.gl|tinyurl|ow\.ly/.test(input)) tactics.push('URL Masking');
        if (lower.includes('update') || lower.includes('reactivate')) tactics.push('Account Hijacking');
        return [...new Set(tactics)];
    }

    function generateExplanation(lower, input, tactics) {
        const reasons = [];
        
        if (lower.includes('urgent') || lower.includes('immediately')) {
            reasons.push('⚠️ Creates artificial urgency to bypass rational thought');
        }
        if (lower.includes('win') || lower.includes('prize')) {
            reasons.push('💰 Promises unrealistic gains - classic financial scam indicator');
        }
        if (lower.includes('click') || lower.includes('verify')) {
            reasons.push('🔗 Requests immediate action on unverified links');
        }
        if (input.includes('@')) {
            reasons.push('🚨 URL structure indicates domain spoofing attempt');
        }
        if (/bit\.ly|t\.co|goo\.gl|tinyurl/.test(input)) {
            reasons.push('🔐 URL shortener masks actual destination');
        }
        if (lower.includes('password') || lower.includes('credit card')) {
            reasons.push('💳 Direct request for sensitive personal/financial data');
        }
        if (lower.includes('alert') || lower.includes('breach')) {
            reasons.push('😨 Emotional manipulation using fake security alerts');
        }
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(input)) {
            reasons.push('🚨 IP address used instead of legitimate domain');
        }

        return reasons.length > 0 
            ? reasons.join(' ') 
            : '✅ No major risk patterns detected - appears legitimate.';
    }

    function getRecommendation(level) {
        const recommendations = {
            'Safe': '✓ Appears legitimate. Standard caution recommended.',
            'Suspicious': '⚠️ Multiple warning signs. Do not click links or share information.',
            'Dangerous': '🚨 High confidence threat. Delete immediately and report if phishing.'
        };
        return recommendations[level] || 'Always verify independently.';
    }

    // ===================== VISUALIZATION =====================
    function visualizeResults(analysis) {
        resultsSection.classList.remove('hidden');
        resultsSection.classList.remove('safe', 'suspicious', 'dangerous');
        resultsSection.classList.add(analysis.riskLevel.toLowerCase());

        // Animate score
        animateScore(analysis.trustScore);

        // Update bars
        animateBar(contentRiskBar, analysis.breakdown.content);
        animateBar(linkRiskBar, analysis.breakdown.link);
        animateBar(intentRiskBar, analysis.breakdown.intent);

        // Update tactics
        tacticsList.innerHTML = '';
        if (analysis.tactics.length === 0) {
            tacticsList.innerHTML = '<span class="no-tags">None Detected</span>';
        } else {
            analysis.tactics.forEach(t => {
                const tag = document.createElement('span');
                tag.className = 'tactic-tag';
                tag.textContent = t;
                tacticsList.appendChild(tag);
            });
        }

        // Update text
        riskLevel.textContent = analysis.riskLevel;
        explanationText.textContent = analysis.explanation;
        insightLine.textContent = generateInsight(analysis);
        insightLine.classList.remove('hidden');
        safetyTip.textContent = analysis.recommendation;
    }

    function animateScore(targetScore) {
        const duration = 1000;
        const start = performance.now();
        const radius = 45;
        const circumference = 2 * Math.PI * radius;
        scoreProgress.style.strokeDasharray = circumference;

        const animate = (now) => {
            const elapsed = now - start;
            const progress = Math.min(elapsed / duration, 1);
            const eased = progress < 0.5 ? 4 * progress ** 3 : 1 - (-2 * progress + 2) ** 3 / 2;
            
            scoreValue.textContent = Math.round(eased * targetScore);
            scoreProgress.style.strokeDashoffset = circumference - (eased * targetScore / 100) * circumference;
            
            if (progress < 1) requestAnimationFrame(animate);
        };
        requestAnimationFrame(animate);
    }

    function animateBar(element, targetWidth) {
        element.style.width = '0%';
        setTimeout(() => {
            element.style.width = Math.min(targetWidth, 100) + '%';
        }, 50);
    }

    function generateInsight(analysis) {
        const { trustScore, tactics } = analysis;
        if (trustScore >= 80) return '✅ This appears to be legitimate communication.';
        if (trustScore >= 60) return '⚠️ Multiple risk factors detected - verify sender independently.';
        return '🚨 HIGH THREAT - Multiple scam indicators. Delete immediately.';
    }

    // ===================== HISTORY MANAGEMENT =====================
    function saveToHistory(analysis) {
        const entry = {
            text: analysis.input.substring(0, 40) + (analysis.input.length > 40 ? '...' : ''),
            score: analysis.trustScore,
            level: analysis.riskLevel,
            time: analysis.timestamp
        };
        
        analysisHistory.unshift(entry);
        if (analysisHistory.length > 15) analysisHistory.pop();
        localStorage.setItem('trustLensHistory', JSON.stringify(analysisHistory));
    }

    function updateHistoryDisplay() {
        if (analysisHistory.length === 0) {
            historySection.classList.add('hidden');
            return;
        }

        historySection.classList.remove('hidden');
        historyList.innerHTML = '';

        analysisHistory.slice(0, 8).forEach(item => {
            const div = document.createElement('div');
            div.className = 'history-item';
            div.innerHTML = `<span>${item.text}</span><span>${item.score} - ${item.level}</span>`;
            div.addEventListener('click', () => {
                trustInput.value = item.text;
                updateCharCount();
                handleAnalyze();
            });
            historyList.appendChild(div);
        });
    }

    function formatReport(analysis) {
        return `TRUSTLENS THREAT ANALYSIS REPORT
================================
Scan Time: ${analysis.timestamp}
Trust Score: ${analysis.trustScore}/100
Threat Level: ${analysis.riskLevel}

ANALYZED CONTENT:
${analysis.input}

THREAT BREAKDOWN:
• Content Risk: ${analysis.breakdown.content}%
• Link Risk: ${analysis.breakdown.link}%
• Intent Risk: ${analysis.breakdown.intent}%

DETECTED TACTICS (${analysis.tactics.length}):
${analysis.tactics.length > 0 ? analysis.tactics.map(t => `  • ${t}`).join('\n') : '  None detected'}

ANALYSIS:
${analysis.explanation}

RECOMMENDATION:
${analysis.recommendation}

---
Powered by TrustLens Security Engine`;
    }

    function showAlert(message) {
        alert(message);
    }

    // ===================== INITIALIZATION =====================
    updateHistoryDisplay();
    console.log('✅ TrustLens Engine Initialized');
});
document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const analyzeBtn = document.getElementById('analyzeBtn');
    const demoBtn = document.getElementById('demoBtn');
    const trustInput = document.getElementById('trustInput');
    const resultsSection = document.getElementById('resultsSection');
    const scoreValue = document.getElementById('scoreValue');
    const scoreProgress = document.getElementById('scoreProgress');
    const riskLevel = document.getElementById('riskLevel');
    const explanationText = document.getElementById('explanationText');
    const insightLine = document.getElementById('insightLine');
    const safetyTip = document.getElementById('safetyTip');
    const charCount = document.getElementById('charCount');
    const copyBtn = document.getElementById('copyBtn');
    const clearBtn = document.getElementById('clearBtn');
    const historySection = document.getElementById('historySection');
    const historyList = document.getElementById('historyList');

    // State
    let analysisHistory = JSON.parse(localStorage.getItem('trustLensHistory')) || [];
    let lastAnalysisResult = null;

    // ============ EVENT LISTENERS ============
    analyzeBtn.addEventListener('click', executeAnalysis);
    copyBtn.addEventListener('click', copyReport);
    clearBtn.addEventListener('click', clearAnalysis);
    
    trustInput.addEventListener('input', () => {
        charCount.textContent = `${trustInput.value.length}/500`;
    });
    
    trustInput.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.key === 'Enter') executeAnalysis();
    });
    
    demoBtn.addEventListener('click', () => {
        trustInput.value = "URGENT! You've won a free iPhone! Click now: bit.ly/free-win";
        charCount.textContent = `${trustInput.value.length}/500`;
        executeAnalysis();
    });

    // ============ MAIN ANALYSIS FUNCTION ============
    function executeAnalysis() {
        const input = trustInput.value.trim();
        if (!input) {
            alert('Please enter content to analyze.');
            return;
        }

        const score = calculateScore(input);
        const level = getRiskLevel(score);
        const explanation = generateExplanation(input);
        const tactics = detectPsychology(input);
        const breakdown = getBreakdown(input);

        displayResults(score, level, explanation, tactics, breakdown, input);
        
        lastAnalysisResult = {
            input,
            score,
            level,
            explanation,
            tactics,
            breakdown
        };

        updateHistory();
    }

    // ============ SCORING ENGINE ============
    function calculateScore(input) {
        let score = 85;
        const lowerInput = input.toLowerCase();

        // 1. URGENCY PATTERNS (weight: 20)
        const urgencyPatterns = ["urgent", "immediately", "asap", "hurry", "fast", "quick", "now", "act now", "don't wait", "limited time", "expires"];
        let urgencyCount = urgencyPatterns.filter(p => lowerInput.includes(p)).length;
        if (urgencyCount > 0) score -= Math.min(urgencyCount * 8, 20);

        // 2. REWARD BAITING (weight: 18)
        const rewardPatterns = ["win", "won", "prize", "reward", "free", "claim", "congratulations", "selected", "gift"];
        let rewardCount = rewardPatterns.filter(p => lowerInput.includes(p)).length;
        if (rewardCount > 0) score -= Math.min(rewardCount * 6, 18);

        // 3. ACTION TRIGGERS (weight: 15)
        const actionPatterns = ["click", "verify", "confirm", "authenticate", "update account", "validate", "reactivate"];
        let actionCount = actionPatterns.filter(p => lowerInput.includes(p)).length;
        if (actionCount > 0) score -= Math.min(actionCount * 5, 15);

        // 4. URL/LINK ANOMALIES (weight: 25)
        if (input.includes("@")) score -= 18;
        const urlShorteners = ["bit.ly", "t.co", "goo.gl", "tinyurl", "ow.ly", "short.link"];
        if (urlShorteners.some(s => input.includes(s))) score -= 12;
        if (input.includes("..") || input.includes("../")) score -= 15;
        if (/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/.test(input)) score -= 10;

        // 5. PRESSURE & SCARCITY (weight: 12)
        const pressurePatterns = ["limited", "exclusive", "act now", "only few left", "hurry", "last chance", "restricted"];
        let pressureCount = pressurePatterns.filter(p => lowerInput.includes(p)).length;
        if (pressureCount > 0) score -= Math.min(pressureCount * 4, 12);

        // 6. EMOTIONAL TRIGGERS (weight: 10)
        const emotionalPatterns = ["afraid", "scared", "alert", "warning", "danger", "security breach", "account locked"];
        let emotionalCount = emotionalPatterns.filter(p => lowerInput.includes(p)).length;
        if (emotionalCount > 0) score -= Math.min(emotionalCount * 3.5, 10);

        // 7. TRUST IMPERSONATION (weight: 15)
        const impersonationPatterns = ["bank", "paypal", "amazon", "apple", "microsoft", "government", "irs", "fbi"];
        let impersonationCount = impersonationPatterns.filter(p => lowerInput.includes(p)).length;
        if (impersonationCount > 1) score -= Math.min(impersonationCount * 5, 15);

        // 8. INFORMATION REQUEST (weight: 10)
        const infoPatterns = ["password", "pin", "ssn", "credit card", "banking details", "personal information"];
        let infoCount = infoPatterns.filter(p => lowerInput.includes(p)).length;
        if (infoCount > 0) score -= Math.min(infoCount * 5, 10);

        return Math.max(Math.min(score, 100), 0);
    }

    function getRiskLevel(score) {
        if (score > 75) return "Safe";
        if (score > 45) return "Suspicious";
        return "Dangerous";
    }

    // ============ STRATEGY DETECTION ============
    function detectPsychology(input) {
        const tactics = [];
        const lower = input.toLowerCase();

        if (lower.includes("urgent") || lower.includes("immediately")) tactics.push("Urgency Pressure");
        if (lower.includes("limited") || lower.includes("exclusive")) tactics.push("Scarcity Manipulation");
        if (lower.includes("win") || lower.includes("free") || lower.includes("prize")) tactics.push("Reward Bait");
        if (lower.includes("click") || lower.includes("confirm") || lower.includes("verify")) tactics.push("Forced Action Trigger");
        if (lower.includes("alert") || lower.includes("warning") || lower.includes("breach")) tactics.push("Fear Exploitation");
        if (lower.includes("congratulation") || lower.includes("selected")) tactics.push("False Validation");
        if (lower.includes("password") || lower.includes("verify identity")) tactics.push("Credential Harvesting");
        if (lower.includes("update") || lower.includes("reactivate")) tactics.push("Account Hijacking");
        if (/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/.test(input)) tactics.push("Domain Spoofing");
        
        return [...new Set(tactics)];
    }

    function getBreakdown(input) {
        let content = 0, link = 0, intent = 0;
        const lower = input.toLowerCase();

        // CONTENT RISK
        const urgencyPatterns = ["urgent", "immediately", "asap", "now", "expires"];
        const rewardPatterns = ["win", "won", "free", "prize", "reward"];
        const emotionalPatterns = ["alert", "warning", "breach", "locked"];
        
        urgencyPatterns.forEach(p => { if (lower.includes(p)) content += 15; });
        rewardPatterns.forEach(p => { if (lower.includes(p)) content += 12; });
        emotionalPatterns.forEach(p => { if (lower.includes(p)) content += 10; });
        content = Math.min(content, 100);

        // LINK RISK
        if (input.includes("@")) link += 35;
        const shorteners = ["bit.ly", "t.co", "goo.gl", "tinyurl", "ow.ly"];
        if (shorteners.some(s => input.includes(s))) link += 25;
        if (input.includes("..") || input.includes("../")) link += 30;
        if (/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/.test(input)) link += 20;
        if ((input.match(/\./g) || []).length > 4) link += 15;
        link = Math.min(link, 100);

        // INTENT RISK
        const actionPatterns = ["click", "verify", "confirm", "authenticate", "update"];
        const pressurePatterns = ["limited", "exclusive", "act now", "only few"];
        const infoPatterns = ["password", "pin", "ssn", "credit card"];
        
        actionPatterns.forEach(p => { if (lower.includes(p)) intent += 20; });
        pressurePatterns.forEach(p => { if (lower.includes(p)) intent += 15; });
        infoPatterns.forEach(p => { if (lower.includes(p)) intent += 25; });
        intent = Math.min(intent, 100);

        return { content, link, intent };
    }

    function generateExplanation(input) {
        let reasons = [];
        const lowerInput = input.toLowerCase();

        // Urgency Detection
        const urgencyPatterns = ["urgent", "immediately", "asap", "now", "expires"];
        if (urgencyPatterns.some(p => lowerInput.includes(p))) {
            reasons.push("⚠️ High-pressure urgency tactics - designed to bypass critical thinking.");
        }

        // Reward Detection
        if (lowerInput.includes("win") || lowerInput.includes("prize")) {
            reasons.push("💰 Unrealistic reward promises - hallmark of financial scams.");
        }

        // Action Exploitation
        if (lowerInput.includes("click") || lowerInput.includes("verify")) {
            reasons.push("🔗 Immediate action requested - typical phishing vector.");
        }

        // URL Spoofing
        if (input.includes("@")) {
            reasons.push("🚨 '@' in URL - domain spoofing detected.");
        }

        // Link Obfuscation
        const shorteners = ["bit.ly", "t.co", "goo.gl", "tinyurl"];
        if (shorteners.some(s => input.includes(s))) {
            reasons.push("🔐 URL shortener hiding destination - phishing tactic.");
        }

        // Information Harvesting
        const infoPatterns = ["password", "pin", "ssn", "credit card"];
        if (infoPatterns.some(p => lowerInput.includes(p))) {
            reasons.push("💳 Requesting sensitive information - harvesting attempt.");
        }

        // Fear Exploitation
        if (lowerInput.includes("alert") || lowerInput.includes("breach")) {
            reasons.push("😨 Sentiment manipulation via fake alerts - creates false urgency.");
        }

        // Trust Impersonation
        const brands = ["paypal", "amazon", "apple", "microsoft", "bank"];
        if (brands.filter(b => lowerInput.includes(b)).length > 0) {
            reasons.push("🎭 Impersonating legitimate company - brand hijacking.");
        }

        if (reasons.length === 0) {
            return "✅ No major risk patterns detected. Content appears structurally sound.";
        }

        return reasons.join(" ");
    }

    function getTips(level) {
        switch(level) {
            case "Safe": return "Trust but verify. Even safe-looking messages can be sophisticated.";
            case "Suspicious": return "Exercise high caution. Do not click links or provide personal information.";
            case "Dangerous": return "Threat confirmed. Recommended action: ignore and delete immediately.";
            default: return "Always verify sources before sharing personal information.";
        }
    }

    function generateDynamicInsight(score, tactics, breakdown) {
        if (score >= 80) {
            return "✅ This appears to be legitimate communication. Exercise normal caution.";
        } else if (score >= 60) {
            const riskiest = Math.max(breakdown.content, breakdown.link, breakdown.intent);
            if (breakdown.link === riskiest) {
                return "⚠️ Suspicious link structure - do not click without verification.";
            }
            return "⚠️ Multiple risk patterns - verify sender before acting.";
        } else {
            return "🚨 HIGH THREAT - Classic scam patterns detected. Delete immediately.";
        }
    }

    // ============ UI DISPLAY ============
    function displayResults(score, level, explanation, tactics, breakdown, input) {
        resultsSection.classList.remove('hidden');
        resultsSection.classList.remove('safe', 'suspicious', 'dangerous');
        resultsSection.classList.add(level.toLowerCase());
        
        setTimeout(() => {
            resultsSection.classList.add('visible');
        }, 10);

        animateScore(score);
        
        document.getElementById('contentRiskBar').style.width = Math.min(breakdown.content, 100) + '%';
        document.getElementById('linkRiskBar').style.width = Math.min(breakdown.link, 100) + '%';
        document.getElementById('intentRiskBar').style.width = Math.min(breakdown.intent, 100) + '%';

        const tacticsList = document.getElementById('tacticsList');
        tacticsList.innerHTML = '';
        if (tactics.length === 0) {
            tacticsList.innerHTML = '<span class="no-tags">None Detected</span>';
        } else {
            tactics.forEach(t => {
                const tag = document.createElement('span');
                tag.className = 'tactic-tag';
                tag.textContent = t;
                tacticsList.appendChild(tag);
            });
        }

        const insights = generateDynamicInsight(score, tactics, breakdown);
        insightLine.textContent = insights;
        insightLine.classList.remove('hidden');

        riskLevel.textContent = level;
        explanationText.textContent = explanation;
        safetyTip.textContent = getTips(level);
    }

    function animateScore(targetScore) {
        let currentScore = 0;
        const duration = 1200;
        const start = performance.now();
        
        const radius = 45;
        const circumference = 2 * Math.PI * radius;
        scoreProgress.style.strokeDasharray = circumference;

        function update(currentTime) {
            const elapsed = currentTime - start;
            const progress = Math.min(elapsed / duration, 1);
            const easedProgress = progress < 0.5 ? 4 * progress * progress * progress : 1 - Math.pow(-2 * progress + 2, 3) / 2;
            
            currentScore = Math.floor(easedProgress * targetScore);
            scoreValue.textContent = currentScore;
            
            const offset = circumference - (easedProgress * targetScore / 100) * circumference;
            scoreProgress.style.strokeDashoffset = offset;

            if (progress < 1) requestAnimationFrame(update);
        }
        
        requestAnimationFrame(update);
    }

    // ============ HISTORY & UTILITIES ============
    function addToHistory(input, score, level) {
        const entry = {
            text: input.substring(0, 50) + (input.length > 50 ? '...' : ''),
            score: score,
            level: level,
            time: new Date().toLocaleTimeString()
        };
        
        analysisHistory.unshift(entry);
        if (analysisHistory.length > 10) analysisHistory.pop();
        localStorage.setItem('trustLensHistory', JSON.stringify(analysisHistory));
    }

    function updateHistory() {
        addToHistory(lastAnalysisResult.input, lastAnalysisResult.score, lastAnalysisResult.level);
        
        if (analysisHistory.length === 0) {
            historySection.classList.add('hidden');
            return;
        }

        historySection.classList.remove('hidden');
        historyList.innerHTML = '';

        analysisHistory.slice(0, 5).forEach((item) => {
            const div = document.createElement('div');
            div.className = 'history-item';
            div.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span>${item.text}</span>
                    <span style="color: var(--text-dim); font-size: 0.7rem;">${item.score} - ${item.level}</span>
                </div>
            `;
            div.addEventListener('click', () => {
                trustInput.value = item.text;
                charCount.textContent = `${item.text.length}/500`;
            });
            historyList.appendChild(div);
        });
    }

    function copyReport() {
        if (!lastAnalysisResult) return;

        const reportText = `
TrustLens Analysis Report
Risk Score: ${lastAnalysisResult.score}/100
Level: ${lastAnalysisResult.level}

Content: ${lastAnalysisResult.input}

Breakdown:
• Content: ${lastAnalysisResult.breakdown.content}%
• Link: ${lastAnalysisResult.breakdown.link}%  
• Intent: ${lastAnalysisResult.breakdown.intent}%

Tactics: ${lastAnalysisResult.tactics.length > 0 ? lastAnalysisResult.tactics.join(', ') : 'None'}

${lastAnalysisResult.explanation}

Recommendation: ${getTips(lastAnalysisResult.level)}
        `;

        navigator.clipboard.writeText(reportText.trim()).then(() => {
            copyBtn.textContent = '✅ Copied!';
            setTimeout(() => copyBtn.textContent = '📋 Copy Report', 2000);
        });
    }

    function clearAnalysis() {
        trustInput.value = '';
        charCount.textContent = '0/500';
        resultsSection.classList.add('hidden');
        lastAnalysisResult = null;
    }
});
    const analyzeBtn = document.getElementById('analyzeBtn');
    const demoBtn = document.getElementById('demoBtn');
    const trustInput = document.getElementById('trustInput');
    const resultsSection = document.getElementById('resultsSection');
    const scoreValue = document.getElementById('scoreValue');
    const scoreProgress = document.getElementById('scoreProgress');
    const riskLevel = document.getElementById('riskLevel');
    const explanationText = document.getElementById('explanationText');
    const insightLine = document.getElementById('insightLine');
    const safetyTip = document.getElementById('safetyTip');

    let analysisHistory = JSON.parse(localStorage.getItem('trustLensHistory')) || [];

    analyzeBtn.addEventListener('click', executeAnalysis);
    
    // Enter key support
    trustInput.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.key === 'Enter') executeAnalysis();
    });
    
    demoBtn.addEventListener('click', () => {
        trustInput.value = "URGENT! You’ve won a free iPhone! Click now: bit.ly/free-win";
        executeAnalysis();
    });

    function executeAnalysis() {
        const input = trustInput.value.trim();
        if (!input) {
            alert('Please enter a URL or content to analyze.');
            return;
        }

        const score = calculateScore(input);
        const level = getRiskLevel(score);
        const explanation = generateExplanation(input);
        const tactics = detectPsychology(input);
        const breakdown = getBreakdown(input);

        displayResults(score, level, explanation, tactics, breakdown, input);
    }

    function calculateScore(input) {
        let score = 85; // Start higher - fewer false positives
        const lowerInput = input.toLowerCase();
        const detectedFactors = [];

        // 1. URGENCY PATTERNS (weight: 20)
        const urgencyPatterns = ["urgent", "immediately", "asap", "hurry", "fast", "quick", "now", "act now", "don't wait", "limited time", "expires"];
        let urgencyCount = 0;
        urgencyPatterns.forEach(pattern => {
            if (lowerInput.includes(pattern)) urgencyCount++;
        });
        if (urgencyCount > 0) {
            score -= Math.min(urgencyCount * 8, 20);
            detectedFactors.push({ type: 'urgency', weight: urgencyCount });
        }

        // 2. REWARD BAITING (weight: 18)
        const rewardPatterns = ["win", "won", "prize", "reward", "free", "claim", "congratulations", "selected", "gift"];
        let rewardCount = 0;
        rewardPatterns.forEach(pattern => {
            if (lowerInput.includes(pattern)) rewardCount++;
        });
        if (rewardCount > 0) {
            score -= Math.min(rewardCount * 6, 18);
            detectedFactors.push({ type: 'reward', weight: rewardCount });
        }

        // 3. ACTION TRIGGERS (weight: 15)
        const actionPatterns = ["click", "verify", "confirm", "authenticate", "update account", "validate", "reactivate"];
        let actionCount = 0;
        actionPatterns.forEach(pattern => {
            if (lowerInput.includes(pattern)) actionCount++;
        });
        if (actionCount > 0) {
            score -= Math.min(actionCount * 5, 15);
            detectedFactors.push({ type: 'action', weight: actionCount });
        }

        // 4. URL/LINK ANOMALIES (weight: 25)
        const urlRisks = [];
        if (input.includes("@")) {
            score -= 18;
            urlRisks.push("'@' in URL - spoofing indicator");
        }
        const urlShorteners = ["bit.ly", "t.co", "goo.gl", "tinyurl", "ow.ly", "short.link"];
        if (urlShorteners.some(s => input.includes(s))) {
            score -= 12;
            urlRisks.push("URL shortener detected - destination obfuscated");
        }
        if (input.includes("..") || input.includes("../")) {
            score -= 15;
            urlRisks.push("Path traversal detected");
        }
        if (/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/.test(input)) {
            score -= 10;
            urlRisks.push("IP address used instead of domain");
        }
        if (urlRisks.length > 0) {
            detectedFactors.push({ type: 'url', risks: urlRisks });
        }

        // 5. PRESSURE & SCARCITY (weight: 12)
        const pressurePatterns = ["limited", "exclusive", "act now", "only few left", "hurry", "last chance", "restricted"];
        let pressureCount = 0;
        pressurePatterns.forEach(pattern => {
            if (lowerInput.includes(pattern)) pressureCount++;
        });
        if (pressureCount > 0) {
            score -= Math.min(pressureCount * 4, 12);
            detectedFactors.push({ type: 'pressure', weight: pressureCount });
        }

        // 6. EMOTIONAL TRIGGERS (weight: 10)
        const emotionalPatterns = ["afraid", "scared", "alert", "warning", "danger", "security breach", "account locked"];
        let emotionalCount = 0;
        emotionalPatterns.forEach(pattern => {
            if (lowerInput.includes(pattern)) emotionalCount++;
        });
        if (emotionalCount > 0) {
            score -= Math.min(emotionalCount * 3.5, 10);
            detectedFactors.push({ type: 'emotional', weight: emotionalCount });
        }

        // 7. TRUST IMPERSONATION (weight: 15)
        const impersonationPatterns = ["bank", "paypal", "amazon", "apple", "microsoft", "government", "irs", "fbi", "claim"];
        let impersonationCount = 0;
        impersonationPatterns.forEach(pattern => {
            if (lowerInput.includes(pattern)) impersonationCount++;
        });
        if (impersonationCount > 1) { // Only flag if multiple
            score -= Math.min(impersonationCount * 5, 15);
            detectedFactors.push({ type: 'impersonation', weight: impersonationCount });
        }

        // 8. INFORMATION REQUEST (weight: 10)
        const infoPatterns = ["password", "pin", "ssn", "credit card", "banking details", "personal information", "verify identity"];
        let infoCount = 0;
        infoPatterns.forEach(pattern => {
            if (lowerInput.includes(pattern)) infoCount++;
        });
        if (infoCount > 0) {
            score -= Math.min(infoCount * 5, 10);
            detectedFactors.push({ type: 'info_request', weight: infoCount });
        }

        // Normalize score
        return Math.max(Math.min(score, 100), 0);
    }

    function getRiskLevel(score) {
        if (score > 75) return "Safe";
        if (score > 45) return "Suspicious";
        return "Dangerous";
    }

    function detectPsychology(input) {
        const tactics = [];
        const lower = input.toLowerCase();

        // Extended psychological triggers
        if (lower.includes("urgent") || lower.includes("immediately")) tactics.push("Urgency Pressure");
        if (lower.includes("limited") || lower.includes("exclusive")) tactics.push("Scarcity Manipulation");
        if (lower.includes("win") || lower.includes("free") || lower.includes("prize")) tactics.push("Reward Bait");
        if (lower.includes("click") || lower.includes("confirm") || lower.includes("verify")) tactics.push("Forced Action Trigger");
        if (lower.includes("alert") || lower.includes("warning") || lower.includes("breach")) tactics.push("Fear Exploitation");
        if (lower.includes("congratulation") || lower.includes("selected")) tactics.push("False Validation");
        if (lower.includes("password") || lower.includes("verify identity")) tactics.push("Credential Harvesting");
        if (lower.includes("update") || lower.includes("reactivate")) tactics.push("Account Hijacking");
        if (/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/.test(input)) tactics.push("Domain Spoofing");
        
        // Deduplicate
        return [...new Set(tactics)];
    }
// CONTENT RISK: Psychological manipulation patterns
        const urgencyPatterns = ["urgent", "immediately", "asap", "now", "don't wait", "expires"];
        const rewardPatterns = ["win", "won", "free", "prize", "claim", "reward"];
        const emotionalPatterns = ["alert", "warning", "breach", "locked", "suspended"];
        
        urgencyPatterns.forEach(p => { if (lower.includes(p)) content += 15; });
        rewardPatterns.forEach(p => { if (lower.includes(p)) content += 12; });
        emotionalPatterns.forEach(p => { if (lower.includes(p)) content += 10; });
        
        content = Math.min(content, 100);

        // Urgency Detection
        const urgencyPatterns = ["urgent", "immediately", "asap", "now", "don't wait", "limited time"];
        if (urgencyPatterns.some(p => lowerInput.includes(p))) {
            reasons.push("⚠️ High-pressure urgency tactics detected - designed to bypass critical thinking.");
        }

        // Reward/Prize Detection
        if (lowerInput.includes("win") || lowerInput.includes("prize") || lowerInput.includes("reward")) {
            reasons.push("💰 Unrealistic reward promises - hallmark of financial scams.");
        }

        // Action Exploitation
        if (lowerInput.includes("click") || lowerInput.includes("verify")) {
            reasons.push("🔗 Immediate action requested - typical phishing/malware delivery vector.");
        }

        // URL Spoofing  
        if (input.includes("@")) {
            reasons.push("🚨 '@' character in URL - indicates domain spoofing attempt (technical attack).");
        }

        // Link Obfuscation
        const shorteners = ["bit.ly", "t.co", "goo.gl", "tinyurl"];
        if (shorteners.some(s => input.includes(s))) {
            reasons.push("🔐 URL shortener used to hide destination - common phishing tactic.");
        }

        // Information Harvesting
        const infoPatterns = ["password", "pin", "ssn", "credit card", "banking"];
        if (infoPatterns.some(p => lowerInput.includes(p))) {
            reasons.push("💳 Requesting sensitive personal/financial information - clear harvesting attempt.");
        }

        // Fear Exploitation
        if (lowerInput.includes("alert") || lowerInput.includes("breach") || lowerInput.includes("locked")) {
            reasons.push("😨 Emo with proper capping
        document.getElementById('contentRiskBar').style.width = Math.min(breakdown.content, 100) + '%';
        document.getElementById('linkRiskBar').style.width = Math.min(breakdown.link, 100) + '%';
        document.getElementById('intentRiskBar').style.width = Math.min(breakdown.intent, 100) + '%';

        // Update Tactics Tags
        const tacticsList = document.getElementById('tacticsList');
        tacticsList.innerHTML = '';
        if (tactics.length === 0) {
            tacticsList.innerHTML = '<span class="no-tags">None Detected</span>';
        } else {
            tactics.forEach(t => {
                const tag = document.createElement('span');
                tag.className = 'tactic-tag';
                tag.textContent = t;
                tacticsList.appendChild(tag);
            });
        }

        // Update Dynamic Insight Line
        const insights = generateDynamicInsight(score, tactics, breakdown);
        insightLine.textContent = insights;
        insightLine.classList.remove('hidden');

        // Update Text
        riskLevel.textContent = level;
        explanationText.textContent = explanation;
        safetyTip.textContent = getTips(level);

        // Save to history
        addToHistory(input, score, ower.includes("verify") || lower.includes("limited")) intent += 70;

        return { content, link, intent };
    }

    function generateExplanation(input) {
        let reasons = [];
        const lowerInput = input.toLowerCase();

        if (lowerInput.includes("urgent")) reasons.push("Detected high-pressure urgency patterns.");
        if (lgenerateDynamicInsight(score, tactics, breakdown) {
        if (score >= 80) {
            return "✅ This appears to be legitimate communication. Exercise normal caution.";
        } else if (score >= 60) {
            const riskiest = Math.max(breakdown.content, breakdown.link, breakdown.intent);
            if (breakdown.link === riskiest) {
                return "⚠️ Suspicious link structure detected - do not click without verification.";
            }
            return "⚠️ Multiple risk patterns detected - verify sender and content before acting.";
        } else {
            return "🚨 HIGH THREAT - This shows classic scam patterns. Delete immediately. Report to authorities if it's phishing.";
        }
    }

    function addToHistory(input, score, level) {
        const entry = {
            text: input.substring(0, 50) + (input.length > 50 ? '...' : ''),
            score: score,
            level: level,
            time: new Date().toLocaleTimeString()
        };
        
        analysisHistory.unshift(entry);
        if (analysisHistory.length > 10) analysisHistory.pop();
        localStorage.setItem('trustLensHistory', JSON.stringify(analysisHistory));
    }

    function animateScore(targetScore) {
        let currentScore = 0;
        const duration = 1200; // 1.2s for smooth animation
        const start = performance.now();
        
        // Circle progress math
        const radius = 45;
        const circumference = 2 * Math.PI * radius;
        scoreProgress.style.strokeDasharray = circumference;

        function update(currentTime) {
            const elapsed = currentTime - start;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing function (outCubic)
            const easedProgress = progress < 0.5 ? 4 * progress * progress * progress : 1 - Math.pow(-2 * progress + 2, 3) / 2o not click links or provide PII.";
            case "Dangerous": return "Threat confirmed. Recommended action: ignore and delete immediately.";
            default: return "Always verify sources before sharing personal information.";
        }
    }

    function displayResults(score, level, explanation, tactics, breakdown, input) {
        // Reset and Show
        resultsSection.classList.remove('hidden');
        resultsSection.classList.remove('safe', 'suspicious', 'dangerous');
        resultsSection.classList.add(level.toLowerCase());
        
        setTimeout(() => {
            resultsSection.classList.add('visible');
        }, 10);

        // Animate Score
        animateScore(score);
        
        // Update Breakdown Bars
        document.getElementById('contentRiskBar').style.width = breakdown.content + '%';
        document.getElementById('linkRiskBar').style.width = breakdown.link + '%';
        document.getElementById('intentRiskBar').style.width = breakdown.intent + '%';

        // Update Tactics Tags
        const tacticsList = document.getElementById('tacticsList');
        tacticsList.innerHTML = '';
        if (tactics.length === 0) {
            tacticsList.innerHTML = '<span class="no-tags">None Detected</span>';
        } else {
            tactics.forEach(t => {
                const tag = document.createElement('span');
                tag.className = 'tactic-tag';
                tag.textContent = t;
                tacticsList.appendChild(tag);
            });
        }

        // Update Human Insight Line
        if (score < 60) {
            insightLine.textContent = "⚠️ This content is trying to manipulate your decision through urgency or reward triggers.";
            insightLine.classList.remove('hidden');
        } else {
            insightLine.classList.add('hidden');
        }

        // Update Text
        riskLevel.textContent = level;
        explanationText.textContent = explanation;
        safetyTip.textContent = getTips(level);
    }

    function animateScore(targetScore) {
        let currentScore = 0;
        const duration = 1000; // 1s
        const start = performance.now();
        
        // Circle progress math
        const radius = 45;
        const circumference = 2 * Math.PI * radius;
        scoreProgress.style.strokeDasharray = circumference;

        function update(currentTime) {
            const elapsed = currentTime - start;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing function (outQuart)
            const easedProgress = 1 - Math.pow(1 - progress, 4);
            
            currentScore = Math.floor(easedProgress * targetScore);
            scoreValue.textContent = currentScore;
            
            const offset = circumference - (easedProgress * targetScore / 100) * circumference;
            scoreProgress.style.strokeDashoffset = offset;

            if (progress < 1) {
                requestAnimationFrame(update);
            }
        }
        
        requestAnimationFrame(update);
    }
});
