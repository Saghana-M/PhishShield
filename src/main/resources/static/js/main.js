/**
 * PhishShield – Main Frontend Application Script
 * Vanilla JavaScript interacting with the Spring Boot REST API (/api/scan)
 */

document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scanForm');
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const btnText = document.getElementById('btnText');
    const errorAlert = document.getElementById('errorAlert');
    const resultsSection = document.getElementById('resultsSection');

    // Result elements
    const resSubmittedUrl = document.getElementById('resSubmittedUrl');
    const resNormalizedUrl = document.getElementById('resNormalizedUrl');
    const resScoreValue = document.getElementById('resScoreValue');
    const resBadge = document.getElementById('resBadge');
    const resDescription = document.getElementById('resDescription');
    const historyBanner = document.getElementById('historyBanner');
    const historyBannerText = document.getElementById('historyBannerText');
    const findingsList = document.getElementById('findingsList');
    const findingsCount = document.getElementById('findingsCount');

    // Quick sample pill buttons
    const pillButtons = document.querySelectorAll('.pill-btn');
    pillButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const sampleUrl = btn.getAttribute('data-url');
            if (sampleUrl) {
                urlInput.value = sampleUrl;
                submitScan(sampleUrl);
            }
        });
    });

    // Form submission
    scanForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const rawUrl = urlInput.value.trim();
        if (!rawUrl) {
            showError("Please enter a valid URL to scan.");
            return;
        }
        submitScan(rawUrl);
    });

    /**
     * Sends the scan request to the backend REST API
     */
    async function submitScan(url) {
        hideError();
        setLoading(true);

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || `Scan failed with status ${response.status}`);
            }

            renderResults(data);

        } catch (err) {
            console.error("Scan error:", err);
            showError(err.message || "Unable to complete scan. Please ensure the backend and MySQL database are active.");
        } finally {
            setLoading(false);
        }
    }

    /**
     * Renders the evaluation results onto the DOM
     */
    function renderResults(data) {
        resSubmittedUrl.textContent = data.submittedUrl || '';
        resNormalizedUrl.textContent = data.normalizedUrl || '';
        resScoreValue.textContent = data.riskScore;

        // Badge styling & classification
        resBadge.textContent = data.riskClassification;
        resBadge.className = 'badge';
        if (data.badgeClass === 'success') {
            resBadge.classList.add('badge-success');
            resScoreValue.style.color = 'var(--status-low-accent)';
        } else if (data.badgeClass === 'warning') {
            resBadge.classList.add('badge-warning');
            resScoreValue.style.color = 'var(--status-suspicious-accent)';
        } else {
            resBadge.classList.add('badge-danger');
            resScoreValue.style.color = 'var(--status-high-accent)';
        }

        resDescription.textContent = data.riskDescription || '';

        // Previous scan information
        if (data.previouslyScanned && data.totalScans > 1) {
            historyBanner.style.display = 'flex';
            historyBannerText.innerHTML = `
                <strong>Prior Submission Detected:</strong> This URL has been analyzed <strong>${data.totalScans} times</strong> in total.
                First seen on <strong>${data.firstSeen || 'N/A'}</strong>; last analyzed on <strong>${data.lastSeen || 'N/A'}</strong>.
            `;
        } else {
            historyBanner.style.display = 'flex';
            historyBannerText.innerHTML = `
                <strong>New URL Submission:</strong> This is the first time this normalized URL has been submitted and stored in PhishShield's database.
            `;
        }

        // Render detected findings
        findingsList.innerHTML = '';
        const findings = data.findings || [];
        findingsCount.textContent = findings.length;

        if (findings.length === 0) {
            findingsList.innerHTML = `
                <div class="no-findings-box">
                    <strong>No Suspicious Indicators Detected</strong>
                    <p style="margin-top: 0.25rem; font-size: 0.9rem;">
                        This URL did not trigger any of the five heuristic warning rules. However, always verify the source of unsolicited communications.
                    </p>
                </div>
            `;
        } else {
            findings.forEach(finding => {
                const card = document.createElement('div');
                card.className = 'finding-card';
                if (finding.points >= 20) {
                    card.classList.add('danger');
                }

                card.innerHTML = `
                    <div class="finding-header">
                        <span class="finding-rule">${escapeHtml(finding.ruleName)}</span>
                        <span class="finding-points">+${finding.points} pts</span>
                    </div>
                    <p class="finding-desc">${escapeHtml(finding.explanation)}</p>
                `;
                findingsList.appendChild(card);
            });
        }

        resultsSection.classList.add('active');
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function setLoading(isLoading) {
        if (isLoading) {
            scanBtn.disabled = true;
            btnText.textContent = 'Analyzing...';
        } else {
            scanBtn.disabled = false;
            btnText.textContent = 'Scan URL';
        }
    }

    function showError(msg) {
        errorAlert.textContent = msg;
        errorAlert.style.display = 'block';
    }

    function hideError() {
        errorAlert.textContent = '';
        errorAlert.style.display = 'none';
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
});
