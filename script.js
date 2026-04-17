// TrustLens - Digital Threat Analysis Engine
console.log('TrustLens Script Loading...');

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM Ready - Initializing TrustLens');

    // ═══════════ DOM ELEMENTS ═══════════
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

    // Verify all elements exist
    if (!analyzeBtn) { console.error('analyzeBtn not found'); return; }
    if (!trustInput) { console.error('trustInput not found'); return; }
    if (!copyBtn) { console.error('copyBtn not found'); return; }
    if (!clearBtn) { console.error('clearBtn not found'); return; }

    console.log('All DOM elements loaded successfully');

    // ═══════════ STATE ═══════════
    let lastAnalysisResult = null;
    let analysisHistory = JSON.parse(localStorage.getItem('trustLensHistory')) || [];

    // ═══════════ EVENT LISTENERS ═══════════
    analyzeBtn.addEventListener('click', () => {
        console.log('Analyze button clicked');
        handleAnalyze();
    });

    clearBtn.addEventListener('click', () => {
        console.log('Clear button clicked');
        handleClear();
    });

    copyBtn.addEventListener('click', () => {
        console.log('Copy button clicked');
        handleCopy();
    });

    trustInput.addEventListener('input', updateCharCount);
    trustInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && e.ctrlKey) handleAnalyze();
    });

    // ═══════════ HANDLERS ═══════════
    function handleAnalyze() {
        const input = trustInput.value.trim();
        
        if (!input.length) {
            alert('⚠️ Please enter content to analyze');
            return;
        }

        if (input.length > 500) {
            alert('⚠️ Content exceeds 500 characters');
            return;
        }

        console.log('Starting analysis for:', input.substring(0, 50));
        
        analyzeBtn.disabled = true;
        analyzeBtn.textContent = '⏳ Analyzing...';

        setTimeout(() => {
            try {
                const analysis = analyzeContent(input);
                console.log('Analysis complete:', analysis);
                
                visualizeResults(analysis);
                lastAnalysisResult = analysis;
                saveToHistory(analysis);
                updateHistoryDisplay();
            } catch (error) {
                console.error('Analysis error:', error);
                alert('Error during analysis: ' + error.message);
            } finally {
                analyzeBtn.disabled = false;
                analyzeBtn.textContent = '🔍 Analyze Now';
            }
        }, 300);
    }

    function handleClear() {
        trustInput.value = '';
        resultsSection.classList.add('hidden');
        lastAnalysisResult = null;
        updateCharCount();
        trustInput.focus();
        console.log('Cleared');
    }

    function handleCopy() {
        if (!lastAnalysisResult) {
            alert('⚠️ No analysis to copy. Analyze content first.');
            return;
        }

        const report = formatReport(lastAnalysisResult);
        navigator.clipboard.writeText(report).then(() => {
            console.log('Copied to clipboard');
            copyBtn.textContent = '✅ Copied!';
            copyBtn.disabled = true;
            setTimeout(() => {
                copyBtn.textContent = '📋 Copy Report';
                copyBtn.disabled = false;
            }, 2000);
        }).catch((error) => {
            console.error('Copy failed:', error);
            copyBtn.textContent = '❌ Copy Failed';
            setTimeout(() => { copyBtn.textContent = '📋 Copy Report'; }, 2000);
        });
    }

    function updateCharCount() {
        const len = trustInput.value.length;
        charCount.textContent = len + '/500';
        
        if (len > 450) charCount.style.color = '#ff6b6b';
        else if (len > 0) charCount.style.color = '#00d9ff';
        else charCount.style.color = '#9090b0';
    }

    // ═══════════ ANALYSIS ENGINE ═══════════
    function analyzeContent(input) {
        const lower = input.toLowerCase();

        // Calculate individual risks
        const urgencyRisk = calculateUrgencyRisk(lower);
        const rewardRisk = calculateRewardRisk(lower);
        const actionRisk = calculateActionRisk(lower);
        const urlRisk = calculateUrlRisk(input);
        const pressureRisk = calculatePressureRisk(lower);
        const emotionalRisk = calculateEmotionalRisk(lower);
        const impersonationRisk = calculateImpersonationRisk(lower);
        const infoRequestRisk = calculateInfoRequestRisk(lower);

        // Weighted total
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

        // Breakdown
        const contentRisk = Math.min(100,
            urgencyRisk * 0.25 + rewardRisk * 0.25 + pressureRisk * 0.2 +
            emotionalRisk * 0.15 + infoRequestRisk * 0.15
        );
        const linkRisk = calculateDimensionalLinkRisk(input);
        const intentRisk = Math.min(100,
            actionRisk * 0.4 + rewardRisk * 0.25 + infoRequestRisk * 0.35
        );

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
            timestamp: new Date().toLocaleString()
        };
    }

    function calculateUrgencyRisk(lower) {
        const patterns = ['urgent', 'immediately', 'asap', 'hurry', 'quickly', 'now', 'act now', 'deadline', 'expires', 'limited time'];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 12);
    }

    function calculateRewardRisk(lower) {
        const patterns = ['win', 'won', 'prize', 'reward', 'free', 'claim', 'congratulations', 'selected', 'gift', 'bonus', 'money', 'cash'];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 10);
    }

    function calculateActionRisk(lower) {
        const patterns = ['click', 'tap', 'verify', 'confirm', 'authenticate', 'update', 'validate', 'reactivate', 'download', 'install'];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 8);
    }

    function calculateUrlRisk(input) {
        let risk = 0;
        if (input.includes('@')) risk += 35;
        if (/bit\.ly|t\.co|goo\.gl|tinyurl|ow\.ly|short\.link|is\.gd/.test(input)) risk += 30;
        if (input.includes('..') || input.includes('../')) risk += 25;
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(input)) risk += 20;
        if ((input.match(/\./g) || []).length > 6) risk += 15;
        if (input.toLowerCase().includes('http://')) risk += 10;
        return Math.min(100, risk);
    }

    function calculateDimensionalLinkRisk(input) {
        let risk = 0;
        if (input.includes('@')) risk += 40;
        if (/bit\.ly|t\.co|goo\.gl|tinyurl|ow\.ly/.test(input)) risk += 35;
        if (input.includes('..') || input.includes('../')) risk += 30;
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(input)) risk += 25;
        if ((input.match(/\./g) || []).length > 6) risk += 20;
        return Math.min(100, risk);
    }

    function calculatePressureRisk(lower) {
        const patterns = ['limited', 'exclusive', 'rare', 'last chance', 'only few', 'restricted', 'members only', 'today only'];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 9);
    }

    function calculateEmotionalRisk(lower) {
        const patterns = ['alert', 'warning', 'danger', 'breach', 'fraud', 'locked', 'suspended', 'compromised', 'attack', 'emergency'];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 7);
    }

    function calculateImpersonationRisk(lower) {
        const brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'bank', 'irs', 'fbi', 'government'];
        const count = brands.filter(b => lower.includes(b)).length;
        return Math.min(100, count > 0 ? count * 15 : 0);
    }

    function calculateInfoRequestRisk(lower) {
        const patterns = ['password', 'pin', 'ssn', 'credit card', 'banking', 'social security', 'account number', 'cvv'];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 12);
    }

    function determineThreatLevel(score) {
        if (score > 75) return 'Safe';
        if (score > 45) return 'Suspicious';
        return 'Dangerous';
    }

    function detectTactics(lower, input) {
        const tactics = [];
        if (lower.includes('urgent') || lower.includes('immediately')) tactics.push('⏰ Urgency Pressure');
        if (lower.includes('limited') || lower.includes('exclusive')) tactics.push('📉 Scarcity Manipulation');
        if (lower.includes('win') || lower.includes('free') || lower.includes('prize')) tactics.push('🎁 Reward Bait');
        if (lower.includes('click') || lower.includes('verify')) tactics.push('🔗 Forced Action');
        if (lower.includes('alert') || lower.includes('warning')) tactics.push('😨 Fear Exploitation');
        if (lower.includes('password') || lower.includes('pin')) tactics.push('🔐 Credential Harvesting');
        if (input.includes('@')) tactics.push('🎭 Domain Spoofing');
        if (/bit\.ly|t\.co|goo\.gl/.test(input)) tactics.push('🔍 URL Masking');
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(input)) tactics.push('💻 IP-Based Spoofing');
        return [...new Set(tactics)].slice(0, 8);
    }

    function generateExplanation(lower, input) {
        const reasons = [];
        if (lower.includes('urgent')) reasons.push('⏰ Artificial urgency detected');
        if (lower.includes('win') || lower.includes('prize')) reasons.push('💰 Unrealistic reward promise');
        if (lower.includes('click') || lower.includes('verify')) reasons.push('🔗 Requests unverified action');
        if (/bit\.ly|t\.co|goo\.gl/.test(input)) reasons.push('🔐 URL shortener masks destination');
        if (lower.includes('password') || lower.includes('credit card')) reasons.push('💳 Requests sensitive data');
        if (lower.includes('alert') || lower.includes('breach')) reasons.push('⚠️ Fake security alert');
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(input)) reasons.push('💻 IP instead of domain');
        return reasons.length > 0 ? reasons.slice(0, 4).join(' ') : '✅ No major red flags detected';
    }

    function getRecommendation(level) {
        const rec = {
            'Safe': '✅ Appears legitimate. Normal caution recommended.',
            'Suspicious': '⚠️ Multiple warning signs detected. Verify independently.',
            'Dangerous': '🚨 High-confidence threat. Delete immediately if phishing.'
        };
        return rec[level] || 'Verify before taking action.';
    }

    // ═══════════ VISUALIZATION ═══════════
    function visualizeResults(analysis) {
        resultsSection.classList.remove('hidden');
        resultsSection.classList.remove('safe', 'suspicious', 'dangerous');
        resultsSection.classList.add(analysis.riskLevel.toLowerCase());

        animateScore(analysis.trustScore);
        animateBar(contentRiskBar, analysis.breakdown.content);
        animateBar(linkRiskBar, analysis.breakdown.link);
        animateBar(intentRiskBar, analysis.breakdown.intent);

        // Update tactics
        tacticsList.innerHTML = '';
        if (analysis.tactics.length === 0) {
            tacticsList.textContent = '✓ None Detected';
        } else {
            analysis.tactics.forEach(t => {
                const span = document.createElement('span');
                span.className = 'tactic-tag';
                span.textContent = t;
                tacticsList.appendChild(span);
            });
        }

        riskLevel.textContent = analysis.riskLevel;
        explanationText.textContent = analysis.explanation;
        safetyTip.textContent = analysis.recommendation;
        insightLine.textContent = generateInsight(analysis);
        insightLine.classList.remove('hidden');

        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function animateScore(target) {
        const duration = 1200;
        const start = performance.now();
        const radius = 54;
        const circumference = 2 * Math.PI * radius;
        scoreProgress.style.strokeDasharray = circumference;

        const animate = (now) => {
            const elapsed = now - start;
            const progress = Math.min(elapsed / duration, 1);
            const eased = progress < 0.5
                ? 4 * progress ** 3
                : 1 - (-2 * progress + 2) ** 3 / 2;

            scoreValue.textContent = Math.round(eased * target);
            scoreProgress.style.strokeDashoffset = circumference - (eased * target / 100) * circumference;

            if (progress < 1) requestAnimationFrame(animate);
        };
        requestAnimationFrame(animate);
    }

    function animateBar(element, target) {
        element.style.width = '0%';
        setTimeout(() => {
            element.style.transition = 'width 1s cubic-bezier(0.34, 1.56, 0.64, 1)';
            element.style.width = Math.min(target, 100) + '%';
        }, 50);
    }

    function generateInsight(analysis) {
        const score = analysis.trustScore;
        if (score >= 80) return '✅ This appears legitimate.';
        if (score >= 60) return '⚠️ Multiple risk factors. Verify independently.';
        if (score >= 45) return '🚨 Expected to be risky. Be cautious.';
        return '⛔ High-confidence threat.';
    }

    // ═══════════ HISTORY ═══════════
    function saveToHistory(analysis) {
        const entry = {
            text: analysis.input.substring(0, 35) + (analysis.input.length > 35 ? '...' : ''),
            score: analysis.trustScore,
            level: analysis.riskLevel,
            time: analysis.timestamp
        };
        analysisHistory.unshift(entry);
        if (analysisHistory.length > 20) analysisHistory.pop();
        localStorage.setItem('trustLensHistory', JSON.stringify(analysisHistory));
    }

    function updateHistoryDisplay() {
        if (analysisHistory.length === 0) {
            historySection.classList.add('hidden');
            return;
        }
        historySection.classList.remove('hidden');
        historyList.innerHTML = '';

        analysisHistory.slice(0, 10).forEach(item => {
            const div = document.createElement('div');
            div.className = 'history-item';
            const badge = item.level === 'Safe' ? '✅' : item.level === 'Suspicious' ? '⚠️' : '🚨';
            div.textContent = item.text + ' — ' + badge + ' ' + item.score;
            div.addEventListener('click', () => {
                trustInput.value = item.text.replace('...', '');
                updateCharCount();
                handleAnalyze();
            });
            historyList.appendChild(div);
        });
    }

    // ═══════════ REPORT ═══════════
    function formatReport(analysis) {
        const lines = [
            '═════════════════════════════════════════',
            'TRUSTLENS THREAT ANALYSIS REPORT',
            '═════════════════════════════════════════',
            '',
            'Scan Time: ' + analysis.timestamp,
            'Trust Score: ' + analysis.trustScore + '/100',
            'Threat Level: ' + analysis.riskLevel,
            '',
            'Content Analyzed:',
            analysis.input,
            '',
            'Risk Breakdown:',
            '• Content Risk: ' + analysis.breakdown.content + '%',
            '• Link Risk: ' + analysis.breakdown.link + '%',
            '• Intent Risk: ' + analysis.breakdown.intent + '%',
            '',
            'Detected Tactics:',
            analysis.tactics.length > 0 ? analysis.tactics.join(', ') : 'None',
            '',
            'Analysis:',
            analysis.explanation,
            '',
            'Recommendation:',
            analysis.recommendation,
            '',
            '═════════════════════════════════════════',
            'Powered by TrustLens Security Engine',
            '═════════════════════════════════════════'
        ];
        return lines.join('\n');
    }

    // ═══════════ INIT ═══════════
    updateHistoryDisplay();
    trustInput.focus();
    console.log('✅ TrustLens Initialized Successfully');
});
// ═══════════════════════════════════════════════════════════════════════════════
// TrustLens - Advanced Digital Trust Analysis Engine
// ═══════════════════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', function() {
    // ─────────────────────── DOM ELEMENTS ───────────────────────
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

    // ─────────────────────── APP STATE ───────────────────────
    let lastAnalysisResult = null;
    let analysisHistory = JSON.parse(localStorage.getItem('trustLensHistory')) || [];

    // ─────────────────────── EVENT LISTENERS ───────────────────────
    analyzeBtn.addEventListener('click', handleAnalyze);
    clearBtn.addEventListener('click', handleClear);
    copyBtn.addEventListener('click', handleCopy);
    trustInput.addEventListener('input', updateCharCount);
    trustInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && e.ctrlKey) handleAnalyze();
    });

    // ─────────────────────── MAIN HANDLERS ───────────────────────
    function handleAnalyze() {
        const input = trustInput.value.trim();
        if (!input.length) {
            showAlert('⚠️ Please enter content to analyze');
            return;
        }
        if (input.length > 500) {
            showAlert('⚠️ Content exceeds 500 characters');
            return;
        }

        analyzeBtn.disabled = true;
        analyzeBtn.textContent = '⏳ Analyzing...';
        
        setTimeout(() => {
            const analysis = analyzeContent(input);
            visualizeResults(analysis);
            lastAnalysisResult = analysis;
            saveToHistory(analysis);
            updateHistoryDisplay();
            
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = '🔍 Analyze Now';
        }, 300);
    }

    function handleClear() {
        trustInput.value = '';
        resultsSection.classList.add('hidden');
        lastAnalysisResult = null;
        updateCharCount();
        trustInput.focus();
    }

    function handleCopy() {
        if (!lastAnalysisResult) return;
        const report = formatReport(lastAnalysisResult);
        navigator.clipboard.writeText(report).then(() => {
            copyBtn.innerHTML = '✅ Copied!';
            copyBtn.disabled = true;
            setTimeout(() => {
                copyBtn.innerHTML = '📋 Copy Report';
                copyBtn.disabled = false;
            }, 2000);
        }).catch(() => {
            copyBtn.innerHTML = '❌ Copy Failed';
            setTimeout(() => { copyBtn.innerHTML = '📋 Copy Report'; }, 2000);
        });
    }

    function updateCharCount() {
        const len = trustInput.value.length;
        charCount.textContent = `${len}/500`;
        if (len > 450) charCount.style.color = '#ff6b6b';
        else if (len > 0) charCount.style.color = '#00d4ff';
        else charCount.style.color = '#9090b0';
    }

    // ─────────────────────── THREAT ANALYSIS ENGINE ───────────────────────
    function analyzeContent(input) {
        const lower = input.toLowerCase();

        // Calculate individual risk factors
        const urgencyRisk = calculateUrgencyRisk(lower);
        const rewardRisk = calculateRewardRisk(lower);
        const actionRisk = calculateActionRisk(lower);
        const urlRisk = calculateUrlRisk(input);
        const pressureRisk = calculatePressureRisk(lower);
        const emotionalRisk = calculateEmotionalRisk(lower);
        const impersonationRisk = calculateImpersonationRisk(lower);
        const infoRequestRisk = calculateInfoRequestRisk(lower);

        // Weighted total risk calculation
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

        // Dimensional breakdown
        const contentRisk = Math.min(100,
            urgencyRisk * 0.25 + rewardRisk * 0.25 + pressureRisk * 0.2 +
            emotionalRisk * 0.15 + infoRequestRisk * 0.15
        );
        const linkRisk = calculateDimensionalLinkRisk(input);
        const intentRisk = Math.min(100,
            actionRisk * 0.4 + rewardRisk * 0.25 + infoRequestRisk * 0.35
        );

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
            timestamp: new Date().toLocaleString(),
            individualRisks: { urgencyRisk, rewardRisk, actionRisk, urlRisk, pressureRisk, emotionalRisk, impersonationRisk, infoRequestRisk }
        };
    }

    // ─────────────────────── RISK CALCULATION FUNCTIONS ───────────────────────
    function calculateUrgencyRisk(lower) {
        const patterns = [
            'urgent', 'immediately', 'asap', 'hurry', 'quickly', 'now',
            'act now', 'don\'t wait', 'deadline', 'expires', 'limited time',
            'time-sensitive', 'right now', 'instant'
        ];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 12);
    }

    function calculateRewardRisk(lower) {
        const patterns = [
            'win', 'won', 'prize', 'reward', 'free', 'claim', 'congratulations',
            'selected', 'gift', 'bonus', 'money', 'cash', 'lucky', 'lottery'
        ];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 10);
    }

    function calculateActionRisk(lower) {
        const patterns = [
            'click', 'tap', 'verify', 'confirm', 'authenticate', 'update',
            'validate', 'reactivate', 'download', 'install', 'enable',
            'proceed', 'submit', 'approve'
        ];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 8);
    }

    function calculateUrlRisk(input) {
        let risk = 0;

        // Domain spoofing patterns
        if (input.includes('@')) risk += 35;

        // URL shorteners (high risk - mask destination)
        if (/bit\.ly|t\.co|goo\.gl|tinyurl|ow\.ly|short\.link|is\.gd|short\.url/.test(input)) risk += 30;

        // Path traversal attempts
        if (input.includes('..') || input.includes('../')) risk += 25;

        // IP addresses instead of domains
        if (/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/.test(input)) risk += 20;

        // Excessive subdomains
        if ((input.match(/\./g) || []).length > 6) risk += 15;

        // Unencrypted HTTP
        if (input.toLowerCase().includes('http://') && !input.toLowerCase().includes('https://')) risk += 10;

        // Check for unusual domain patterns
        if (/\.\w{1,2}[\/\?#]|localhost|internal/.test(input)) risk += 12;

        return Math.min(100, risk);
    }

    function calculateDimensionalLinkRisk(input) {
        let risk = 0;
        if (input.includes('@')) risk += 40;
        if (/bit\.ly|t\.co|goo\.gl|tinyurl|ow\.ly|short/.test(input)) risk += 35;
        if (input.includes('..') || input.includes('../')) risk += 30;
        if (/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/.test(input)) risk += 25;
        if ((input.match(/\./g) || []).length > 6) risk += 20;
        return Math.min(100, risk);
    }

    function calculatePressureRisk(lower) {
        const patterns = [
            'limited', 'exclusive', 'rare', 'last chance', 'only few',
            'restricted', 'members only', 'invitation only', 'today only',
            'disappearing', 'hurry', 'fast'
        ];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 9);
    }

    function calculateEmotionalRisk(lower) {
        const patterns = [
            'alert', 'warning', 'danger', 'breach', 'fraud', 'locked',
            'suspended', 'compromised', 'attack', 'concerned', 'urgent',
            'emergency', 'crisis', 'disaster'
        ];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 7);
    }

    function calculateImpersonationRisk(lower) {
        const brands = [
            'paypal', 'amazon', 'apple', 'microsoft', 'google', 'bank',
            'irs', 'fbi', 'government', 'revenue', 'twitter', 'facebook',
            'instagram', 'whatsapp', 'telegram'
        ];
        const count = brands.filter(b => lower.includes(b)).length;
        return Math.min(100, count > 0 ? count * 15 : 0);
    }

    function calculateInfoRequestRisk(lower) {
        const patterns = [
            'password', 'pin', 'ssn', 'credit card', 'banking', 'social security',
            'account number', 'routing', 'cvv', 'security questions', 'verification code',
            'secret', 'confidential'
        ];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 12);
    }

    function determineThreatLevel(score) {
        if (score > 75) return 'Safe';
        if (score > 45) return 'Suspicious';
        return 'Dangerous';
    }

    // ─────────────────────── TACTIC DETECTION ───────────────────────
    function detectTactics(lower, input) {
        const tactics = [];

        if (lower.includes('urgent') || lower.includes('immediately')) tactics.push('⏰ Urgency Pressure');
        if (lower.includes('limited') || lower.includes('exclusive')) tactics.push('📉 Scarcity Manipulation');
        if (lower.includes('win') || lower.includes('free') || lower.includes('prize')) tactics.push('🎁 Reward Bait');
        if (lower.includes('click') || lower.includes('verify') || lower.includes('confirm')) tactics.push('🔗 Forced Action');
        if (lower.includes('alert') || lower.includes('warning') || lower.includes('breach')) tactics.push('😨 Fear Exploitation');
        if (lower.includes('congratulations') || lower.includes('selected')) tactics.push('🏆 False Validation');
        if (lower.includes('password') || lower.includes('pin') || lower.includes('cvv')) tactics.push('🔐 Credential Harvesting');
        if (input.includes('@') && !/@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(input)) tactics.push('🎭 Domain Spoofing');
        if (/bit\.ly|t\.co|goo\.gl|tinyurl|ow\.ly/.test(input)) tactics.push('🔍 URL Masking');
        if (lower.includes('update') || lower.includes('reactivate')) tactics.push('🔄 Account Hijacking');
        if (lower.includes('confirm identity') || lower.includes('verify account')) tactics.push('👤 Identity Verification Scam');
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(input)) tactics.push('💻 IP-Based Spoofing');

        return [...new Set(tactics)].slice(0, 8);
    }

    // ─────────────────────── EXPLANATION GENERATION ───────────────────────
    function generateExplanation(lower, input, tactics) {
        const reasons = [];

        if (lower.includes('urgent') || lower.includes('immediately'))
            reasons.push('⏰ Creates artificial urgency to bypass rational thought');
        if (lower.includes('win') || lower.includes('prize'))
            reasons.push('💰 Promises unrealistic gains - classic financial scam indicator');
        if (lower.includes('click') || lower.includes('verify'))
            reasons.push('🔗 Requests immediate action on unverified links');
        if (input.includes('@') && !/@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(input))
            reasons.push('🎭 Email structure shows spoofing attempts');
        if (/bit\.ly|t\.co|goo\.gl|tinyurl|short/.test(input))
            reasons.push('🔐 URL shortener masks actual destination');
        if (lower.includes('password') || lower.includes('credit card') || lower.includes('cvv'))
            reasons.push('💳 Direct request for sensitive personal/financial data');
        if (lower.includes('alert') || lower.includes('breach') || lower.includes('suspended'))
            reasons.push('⚠️ Emotional manipulation using fake security alerts');
        if (/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/.test(input))
            reasons.push('💻 IP address used instead of legitimate domain');
        if (lower.includes('limited time') || lower.includes('act now'))
            reasons.push('⏳ Artificial scarcity creates pressure to act without thinking');

        return reasons.length > 0
            ? reasons.slice(0, 5).join(' ')
            : '✅ No major risk patterns detected - appears legitimate.';
    }

    function getRecommendation(level) {
        const recommendations = {
            'Safe': '✅ Appears legitimate. Standard caution recommended.',
            'Suspicious': '⚠️ Multiple warning signs. Verify independently before taking action.',
            'Dangerous': '🚨 High-confidence threat. Delete immediately and report if phishing/scam.'
        };
        return recommendations[level] || 'Always verify sources independently.';
    }

    // ─────────────────────── VISUALIZATION ───────────────────────
    function visualizeResults(analysis) {
        resultsSection.classList.remove('hidden');
        resultsSection.classList.remove('safe', 'suspicious', 'dangerous');
        resultsSection.classList.add(analysis.riskLevel.toLowerCase());

        animateScore(analysis.trustScore);
        animateBar(contentRiskBar, analysis.breakdown.content);
        animateBar(linkRiskBar, analysis.breakdown.link);
        animateBar(intentRiskBar, analysis.breakdown.intent);

        // Update tactics
        tacticsList.innerHTML = '';
        if (analysis.tactics.length === 0) {
            tacticsList.innerHTML = '<span class="no-tags">✓ None Detected</span>';
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

        // Smooth scroll
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function animateScore(targetScore) {
        const duration = 1200;
        const start = performance.now();
        const radius = 45;
        const circumference = 2 * Math.PI * radius;
        scoreProgress.style.strokeDasharray = circumference;

        const animate = (now) => {
            const elapsed = now - start;
            const progress = Math.min(elapsed / duration, 1);
            const eased = progress < 0.5
                ? 4 * progress ** 3
                : 1 - (-2 * progress + 2) ** 3 / 2;

            scoreValue.textContent = Math.round(eased * targetScore);
            scoreProgress.style.strokeDashoffset = circumference - (eased * targetScore / 100) * circumference;

            if (progress < 1) requestAnimationFrame(animate);
        };
        requestAnimationFrame(animate);
    }

    function animateBar(element, targetWidth) {
        element.style.width = '0%';
        setTimeout(() => {
            element.style.transition = 'width 1s cubic-bezier(0.34, 1.56, 0.64, 1)';
            element.style.width = Math.min(targetWidth, 100) + '%';
        }, 50);
    }

    function generateInsight(analysis) {
        const { trustScore } = analysis;
        if (trustScore >= 80) return '✅ SAFE: This appears to be legitimate communication.';
        if (trustScore >= 60) return '⚠️ CAUTION: Verify sender independently before taking action.';
        if (trustScore >= 45) return '🚨 WARNING: Multiple risk factors detected.';
        return '⛔ DANGER: High-confidence threat detected.';
    }

    // ─────────────────────── HISTORY MANAGEMENT ───────────────────────
    function saveToHistory(analysis) {
        const entry = {
            text: analysis.input.substring(0, 35) + (analysis.input.length > 35 ? '...' : ''),
            score: analysis.trustScore,
            level: analysis.riskLevel,
            time: analysis.timestamp
        };
        analysisHistory.unshift(entry);
        if (analysisHistory.length > 20) analysisHistory.pop();
        localStorage.setItem('trustLensHistory', JSON.stringify(analysisHistory));
    }

    function updateHistoryDisplay() {
        if (analysisHistory.length === 0) {
            historySection.classList.add('hidden');
            return;
        }
        historySection.classList.remove('hidden');
        historyList.innerHTML = '';

        analysisHistory.slice(0, 10).forEach((item, index) => {
            const div = document.createElement('div');
            div.className = 'history-item';
            const statusIcon = item.level === 'Safe' ? '✅' : item.level === 'Suspicious' ? '⚠️' : '🚨';
            div.innerHTML = `
                <div class="history-content">
                    <span class="history-text">${item.text}</span>
                    <span class="history-time">${item.time}</span>
                </div>
                <span class="history-badge ${item.level.toLowerCase()}">${statusIcon} ${item.score}</span>
            `;
            div.addEventListener('click', () => {
                trustInput.value = item.text.replace('...', '');
                updateCharCount();
                handleAnalyze();
            });
            historyList.appendChild(div);
        });
    }

    // ─────────────────────── REPORT FORMATTING ───────────────────────
    function formatReport(analysis) {
        return `
╔════════════════════════════════════════════════════════════════╗
║          TRUSTLENS THREAT ANALYSIS REPORT                       ║
╚════════════════════════════════════════════════════════════════╝

📅 SCAN TIME: ${analysis.timestamp}
📊 TRUST SCORE: ${analysis.trustScore}/100
🎯 THREAT LEVEL: ${analysis.riskLevel}

┌─ Analyzed Content ─────────────────────────────────────────┐
${analysis.input}
└────────────────────────────────────────────────────────────┘

┌─ Risk Breakdown ───────────────────────────────────────────┐
• Content Risk: ${analysis.breakdown.content}% ${getBar(analysis.breakdown.content)}
• Link Risk:    ${analysis.breakdown.link}% ${getBar(analysis.breakdown.link)}
• Intent Risk:  ${analysis.breakdown.intent}% ${getBar(analysis.breakdown.intent)}
└────────────────────────────────────────────────────────────┘

┌─ Detected Tactics (${analysis.tactics.length}) ──────────────────────┐
${analysis.tactics.length > 0
            ? analysis.tactics.map(t => `  • ${t}`).join('\n')
            : '  ✓ None detected'}
└────────────────────────────────────────────────────────────┘

┌─ Analysis ─────────────────────────────────────────────────┐
${analysis.explanation}
└────────────────────────────────────────────────────────────┘

┌─ Recommendation ───────────────────────────────────────────┐
${analysis.recommendation}
└────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════
            Powered by TrustLens Security Engine
═══════════════════════════════════════════════════════════════
`;
    }

    function getBar(value) {
        const filled = Math.round(value / 10);
        const empty = 10 - filled;
        return '[' + '█'.repeat(filled) + '░'.repeat(empty) + ']';
    }

    function showAlert(message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert-toast';
        alertDiv.textContent = message;
        document.body.appendChild(alertDiv);

        setTimeout(() => alertDiv.classList.add('show'), 10);
        setTimeout(() => {
            alertDiv.classList.remove('show');
            setTimeout(() => alertDiv.remove(), 300);
        }, 3000);
    }

    // ─────────────────────── INITIALIZATION ───────────────────────
    updateHistoryDisplay();
    trustInput.focus();
    console.log('✅ TrustLens Engine Initialized - Ready for analysis');
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
            copyBtn.textContent = '? Copied!';
            setTimeout(() => { copyBtn.textContent = '?? Copy Report'; }, 2000);
        }).catch(() => {
            copyBtn.textContent = '? Error!';
            setTimeout(() => { copyBtn.textContent = '?? Copy Report'; }, 2000);
        });
    }

    function updateCharCount() {
        const len = trustInput.value.length;
        charCount.textContent = $+${len}/500+`;
        if (len > 450) charCount.style.color = '#ff3860';
        else charCount.style.color = '#3d85ff';
    }

    // ===================== THREAT ANALYSIS ENGINE =====================
    function analyzeContent(input) {
        const lower = input.toLowerCase();
        const urgencyRisk = calculateUrgencyRisk(lower);
        const rewardRisk = calculateRewardRisk(lower);
        const actionRisk = calculateActionRisk(lower);
        const urlRisk = calculateUrlRisk(input);
        const pressureRisk = calculatePressureRisk(lower);
        const emotionalRisk = calculateEmotionalRisk(lower);
        const impersonationRisk = calculateImpersonationRisk(lower);
        const infoRequestRisk = calculateInfoRequestRisk(lower);
        const totalRisk = urgencyRisk * 0.15 + rewardRisk * 0.14 + actionRisk * 0.12 + urlRisk * 0.20 + pressureRisk * 0.10 + emotionalRisk * 0.08 + impersonationRisk * 0.12 + infoRequestRisk * 0.09;
        const trustScore = Math.max(0, Math.min(100, 100 - totalRisk));
        const riskLevel = determineThreatLevel(trustScore);
        const tactics = detectTactics(lower, input);
        const contentRisk = Math.min(100, urgencyRisk * 0.25 + rewardRisk * 0.25 + pressureRisk * 0.2 + emotionalRisk * 0.15 + infoRequestRisk * 0.15);
        const linkRisk = calculateDimensionalLinkRisk(input);
        const intentRisk = Math.min(100, actionRisk * 0.4 + rewardRisk * 0.25 + infoRequestRisk * 0.35);
        return { input, trustScore: Math.round(trustScore), riskLevel, tactics, breakdown: { content: Math.round(contentRisk), link: Math.round(linkRisk), intent: Math.round(intentRisk) }, explanation: generateExplanation(lower, input, tactics), recommendation: getRecommendation(riskLevel), timestamp: new Date().toLocaleTimeString() };
    }

    function calculateUrgencyRisk(lower) {
        const patterns = ['urgent', 'immediately', 'asap', 'hurry', 'quickly', 'now', 'act now', 'don\'t wait', 'deadline', 'expires', 'limited time', 'time-sensitive'];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 15);
    }

    function calculateRewardRisk(lower) {
        const patterns = ['win', 'won', 'prize', 'reward', 'free', 'claim', 'congratulations', 'selected', 'gift', 'bonus', 'money', 'cash'];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 12);
    }

    function calculateActionRisk(lower) {
        const patterns = ['click', 'tap', 'verify', 'confirm', 'authenticate', 'update', 'validate', 'reactivate', 'download', 'install'];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 10);
    }

    function calculateUrlRisk(input) {
        let risk = 0;
        if (input.includes('@')) risk += 30;
        if (/bit\.ly|t\.co|goo\.gl|tinyurl|ow\.ly|short\.link|is\.gd/.test(input)) risk += 25;
        if (input.includes('..') || input.includes('../')) risk += 20;
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(input)) risk += 15;
        if ((input.match(/\./g) || []).length > 5) risk += 10;
        if (input.toLowerCase().includes('http://')) risk += 5;
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
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 10);
    }

    function calculateEmotionalRisk(lower) {
        const patterns = ['alert', 'warning', 'danger', 'breach', 'fraud', 'locked', 'suspended', 'compromised', 'attack', 'concerned'];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 8);
    }

    function calculateImpersonationRisk(lower) {
        const brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'bank', 'irs', 'fbi', 'government', 'revenue'];
        const count = brands.filter(b => lower.includes(b)).length;
        return Math.min(100, count > 1 ? count * 12 : 0);
    }

    function calculateInfoRequestRisk(lower) {
        const patterns = ['password', 'pin', 'ssn', 'credit card', 'banking', 'social security', 'account number', 'routing'];
        return Math.min(100, patterns.filter(p => lower.includes(p)).length * 15);
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
        if (lower.includes('urgent') || lower.includes('immediately')) reasons.push('?? Creates artificial urgency to bypass rational thought');
        if (lower.includes('win') || lower.includes('prize')) reasons.push('?? Promises unrealistic gains - classic financial scam indicator');
        if (lower.includes('click') || lower.includes('verify')) reasons.push('?? Requests immediate action on unverified links');
        if (input.includes('@')) reasons.push('?? URL structure indicates domain spoofing attempt');
        if (/bit\.ly|t\.co|goo\.gl|tinyurl/.test(input)) reasons.push('?? URL shortener masks actual destination');
        if (lower.includes('password') || lower.includes('credit card')) reasons.push('?? Direct request for sensitive personal/financial data');
        if (lower.includes('alert') || lower.includes('breach')) reasons.push('?? Emotional manipulation using fake security alerts');
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(input)) reasons.push('?? IP address used instead of legitimate domain');
        return reasons.length > 0 ? reasons.join(' ') : '? No major risk patterns detected - appears legitimate.';
    }

    function getRecommendation(level) {
        return { 'Safe': '? Appears legitimate. Standard caution recommended.', 'Suspicious': '?? Multiple warning signs. Do not click links or share information.', 'Dangerous': '?? High confidence threat. Delete immediately and report if phishing.' }[level] || 'Always verify independently.';
    }

    function visualizeResults(analysis) {
        resultsSection.classList.remove('hidden', 'safe', 'suspicious', 'dangerous');
        resultsSection.classList.add(analysis.riskLevel.toLowerCase());
        animateScore(analysis.trustScore);
        animateBar(contentRiskBar, analysis.breakdown.content);
        animateBar(linkRiskBar, analysis.breakdown.link);
        animateBar(intentRiskBar, analysis.breakdown.intent);
        tacticsList.innerHTML = '';
        analysis.tactics.length === 0 ? tacticsList.innerHTML = '<span class=\"no-tags\">None Detected</span>' : analysis.tactics.forEach(t => { const tag = document.createElement('span'); tag.className = 'tactic-tag'; tag.textContent = t; tacticsList.appendChild(tag); });
        riskLevel.textContent = analysis.riskLevel;
        explanationText.textContent = analysis.explanation;
        insightLine.textContent = generateInsight(analysis);
        insightLine.classList.remove('hidden');
        safetyTip.textContent = analysis.recommendation;
    }

    function animateScore(targetScore) {
        const duration = 1000, start = performance.now(), radius = 45, circumference = 2 * Math.PI * radius;
        scoreProgress.style.strokeDasharray = circumference;
        const animate = (now) => {
            const elapsed = now - start, progress = Math.min(elapsed / duration, 1), eased = progress < 0.5 ? 4 * progress ** 3 : 1 - (-2 * progress + 2) ** 3 / 2;
            scoreValue.textContent = Math.round(eased * targetScore);
            scoreProgress.style.strokeDashoffset = circumference - (eased * targetScore / 100) * circumference;
            if (progress < 1) requestAnimationFrame(animate);
        };
        requestAnimationFrame(animate);
    }

    function animateBar(element, targetWidth) {
        element.style.width = '0%';
        setTimeout(() => { element.style.width = Math.min(targetWidth, 100) + '%'; }, 50);
    }

    function generateInsight(analysis) {
        if (analysis.trustScore >= 80) return '? This appears to be legitimate communication.';
        if (analysis.trustScore >= 60) return '?? Multiple risk factors detected - verify sender independently.';
        return '?? HIGH THREAT - Multiple scam indicators. Delete immediately.';
    }

    function saveToHistory(analysis) {
        const entry = { text: analysis.input.substring(0, 40) + (analysis.input.length > 40 ? '...' : ''), score: analysis.trustScore, level: analysis.riskLevel, time: analysis.timestamp };
        analysisHistory.unshift(entry);
        if (analysisHistory.length > 15) analysisHistory.pop();
        localStorage.setItem('trustLensHistory', JSON.stringify(analysisHistory));
    }

    function updateHistoryDisplay() {
        if (analysisHistory.length === 0) { historySection.classList.add('hidden'); return; }
        historySection.classList.remove('hidden');
        historyList.innerHTML = '';
        analysisHistory.slice(0, 8).forEach(item => {
            const div = document.createElement('div');
            div.className = 'history-item';
            div.innerHTML = <span>+${item.text}+</span><span>+${item.score} - +${item.level}+</span>;
            div.addEventListener('click', () => { trustInput.value = item.text; updateCharCount(); handleAnalyze(); });
            historyList.appendChild(div);
        });
    }

    function formatReport(analysis) {
        return TRUSTLENS THREAT ANALYSIS REPORT
================================
Scan Time: +${analysis.timestamp}+
Trust Score: +${analysis.trustScore}+/100
Threat Level: +${analysis.riskLevel}+

ANALYZED CONTENT:
+${analysis.input}+

THREAT BREAKDOWN:
� Content Risk: +${analysis.breakdown.content}+%
� Link Risk: +${analysis.breakdown.link}+%
� Intent Risk: +${analysis.breakdown.intent}+%

DETECTED TACTICS (+${analysis.tactics.length}+):
+${analysis.tactics.length > 0 ? analysis.tactics.map(t =>   � +${t}).join('\n') : '  None detected'}+

ANALYSIS:
+${analysis.explanation}+

RECOMMENDATION:
+${analysis.recommendation}+

---
Powered by TrustLens Security Engine;
    }

    function showAlert(message) {
        alert(message);
    }

    updateHistoryDisplay();
    console.log('? TrustLens Engine Initialized');
});
