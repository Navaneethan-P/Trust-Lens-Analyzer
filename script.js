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

    analyzeBtn.addEventListener('click', executeAnalysis);
    
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
        let score = 100;
        const lowerInput = input.toLowerCase();

        // Keyword checking
        const badWords = ["urgent", "win", "click", "free", "offer", "prize", "gift", "limited", "verify"];
        badWords.forEach(word => {
            if (lowerInput.includes(word)) {
                score -= 15;
            }
        });

        // URL Pattern checking
        if (input.includes("@") || input.includes("bit.ly") || input.includes("t.co") || input.includes("goo.gl")) {
            score -= 30;
        }

        // Structural checks
        if ((input.match(/\./g) || []).length > 3) {
            score -= 10; // Multiple subdomains
        }

        return Math.max(score, 0);
    }

    function getRiskLevel(score) {
        if (score > 75) return "Safe";
        if (score > 45) return "Suspicious";
        return "Dangerous";
    }

    function detectPsychology(input) {
        const tactics = [];
        const lower = input.toLowerCase();

        if (lower.includes("urgent")) tactics.push("Urgency Pressure");
        if (lower.includes("limited")) tactics.push("Scarcity Manipulation");
        if (lower.includes("win") || lower.includes("free")) tactics.push("Reward Bait");
        if (lower.includes("click")) tactics.push("Forced Action Trigger");
        
        return tactics;
    }

    function getBreakdown(input) {
        let content = 0;
        let link = 0;
        let intent = 0;
        const lower = input.toLowerCase();

        if (lower.includes("urgent") || lower.includes("win") || lower.includes("offer")) content += 60;
        if (input.includes("@") || input.includes("bit.ly") || input.includes("t.co") || (input.match(/\./g) || []).length > 2) link += 80;
        if (lower.includes("click") || lower.includes("verify") || lower.includes("limited")) intent += 70;

        return { content, link, intent };
    }

    function generateExplanation(input) {
        let reasons = [];
        const lowerInput = input.toLowerCase();

        if (lowerInput.includes("urgent")) reasons.push("Detected high-pressure urgency patterns.");
        if (lowerInput.includes("win") || lowerInput.includes("prize")) reasons.push("Promises unrealistic rewards (common scam tactic).");
        if (lowerInput.includes("click") || lowerInput.includes("free")) reasons.push("Encourages immediate action on unverified links.");
        if (input.includes("@")) reasons.push("Suspicious URL structure with '@' character detected.");
        if (input.includes("bit.ly") || input.includes("t.co")) reasons.push("Uses URL shorteners to mask destination.");
        
        if (reasons.length === 0) {
            return "No obvious risk patterns detected. Content appears structurally sound.";
        }

        return reasons.join(" ");
    }

    function getTips(level) {
        switch(level) {
            case "Safe": return "Trust but verify. Even safe-looking messages can be sophisticated.";
            case "Suspicious": return "Exercise high caution. Do not click links or provide PII.";
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
