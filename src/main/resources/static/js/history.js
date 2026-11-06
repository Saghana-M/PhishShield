/**
 * PhishShield – Scan History Page Script
 * Interacts with /api/history and /api/history/{scanId}
 */

document.addEventListener('DOMContentLoaded', () => {
    const historyTableBody = document.getElementById('historyTableBody');
    const filterInput = document.getElementById('filterInput');
    const refreshBtn = document.getElementById('refreshBtn');

    // Modal elements
    const detailsModal = document.getElementById('detailsModal');
    const modalCloseBtn = document.getElementById('modalCloseBtn');
    const modalDismissBtn = document.getElementById('modalDismissBtn');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    let allScans = [];

    // Load initial history
    fetchHistory();

    // Event listeners
    refreshBtn.addEventListener('click', fetchHistory);

    filterInput.addEventListener('input', () => {
        const query = filterInput.value.toLowerCase().trim();
        const filtered = allScans.filter(scan => {
            const url = (scan.scannedUrl || '').toLowerCase();
            const status = (scan.scanStatus || '').toLowerCase();
            return url.includes(query) || status.includes(query);
        });
        renderTable(filtered);
    });

    modalCloseBtn.addEventListener('click', closeModal);
    modalDismissBtn.addEventListener('click', closeModal);
    detailsModal.addEventListener('click', (e) => {
        if (e.target === detailsModal) {
            closeModal();
        }
    });

    /**
     * Fetches recent scan history from REST API
     */
    async function fetchHistory() {
        historyTableBody.innerHTML = `
            <tr>
                <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">
                    Loading scan history...
                </td>
            </tr>
        `;

        try {
            const res = await fetch('/api/history?limit=50');
            if (!res.ok) {
                throw new Error(`Failed to load history (Status: ${res.status})`);
            }
            allScans = await res.json();
            renderTable(allScans);
        } catch (err) {
            console.error("History fetch error:", err);
            historyTableBody.innerHTML = `
                <tr>
                    <td colspan="7" style="text-align: center; color: var(--status-high-text); padding: 2rem;">
                        Unable to connect to database or fetch scan records. Ensure the backend server and MySQL are running.
                    </td>
                </tr>
            `;
        }
    }

    /**
     * Renders rows into the scan history table
     */
    function renderTable(scans) {
        if (!scans || scans.length === 0) {
            historyTableBody.innerHTML = `
                <tr>
                    <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">
                        No scan history found. Scan some URLs from the Scanner tab to populate this table.
                    </td>
                </tr>
            `;
            return;
        }

        historyTableBody.innerHTML = '';
        scans.forEach(scan => {
            const tr = document.createElement('tr');

            let badgeClass = 'badge-success';
            if (scan.scanStatus === 'Suspicious') badgeClass = 'badge-warning';
            if (scan.scanStatus === 'High Risk') badgeClass = 'badge-danger';

            tr.innerHTML = `
                <td>#${scan.scanId}</td>
                <td class="table-url-cell" title="${escapeHtml(scan.scannedUrl)}">${escapeHtml(scan.scannedUrl)}</td>
                <td><strong>${scan.scanScore}</strong> / 100</td>
                <td><span class="badge ${badgeClass}">${escapeHtml(scan.scanStatus)}</span></td>
                <td>${escapeHtml(scan.scannedAt || 'N/A')}</td>
                <td><span style="font-weight: 600;">${scan.totalPreviousScans || 1}</span></td>
                <td>
                    <button class="btn btn-primary btn-sm view-details-btn" data-scan-id="${scan.scanId}">
                        View Details
                    </button>
                </td>
            `;

            historyTableBody.appendChild(tr);
        });

        // Attach detail button listeners
        document.querySelectorAll('.view-details-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const scanId = btn.getAttribute('data-scan-id');
                openScanDetails(scanId);
            });
        });
    }

    /**
     * Fetches details of an individual scan and opens modal
     */
    async function openScanDetails(scanId) {
        modalTitle.textContent = `Scan Details #${scanId}`;
        modalBody.innerHTML = '<p style="color: var(--text-muted);">Loading findings...</p>';
        detailsModal.classList.add('active');

        try {
            const res = await fetch(`/api/history/${scanId}`);
            if (!res.ok) {
                throw new Error("Failed to load details for scan #" + scanId);
            }
            const scan = await res.json();
            renderModalContent(scan);
        } catch (err) {
            modalBody.innerHTML = `<p style="color: var(--status-high-text);">${escapeHtml(err.message)}</p>`;
        }
    }

    function renderModalContent(scan) {
        let badgeClass = 'badge-success';
        if (scan.scanStatus === 'Suspicious') badgeClass = 'badge-warning';
        if (scan.scanStatus === 'High Risk') badgeClass = 'badge-danger';

        let findingsHtml = '';
        const findings = scan.findings || [];

        if (findings.length === 0) {
            findingsHtml = `
                <div class="no-findings-box" style="margin-top: 1rem;">
                    <strong>No Warning Signs Detected</strong>
                    <p style="font-size: 0.85rem; margin-top: 0.2rem;">This scan did not trigger any heuristic detection rules.</p>
                </div>
            `;
        } else {
            findingsHtml = '<div style="margin-top: 1rem;">';
            findings.forEach(f => {
                findingsHtml += `
                    <div class="finding-card ${f.points >= 20 ? 'danger' : ''}">
                        <div class="finding-header">
                            <span class="finding-rule">${escapeHtml(f.ruleName)}</span>
                            <span class="finding-points">+${f.points} pts</span>
                        </div>
                        <p class="finding-desc">${escapeHtml(f.explanation)}</p>
                    </div>
                `;
            });
            findingsHtml += '</div>';
        }

        modalBody.innerHTML = `
            <div style="margin-bottom: 1rem;">
                <div class="url-label">Scanned URL</div>
                <div class="url-text" style="word-break: break-all; max-width: 100%;">${escapeHtml(scan.scannedUrl)}</div>
            </div>

            <div style="display: flex; gap: 1.5rem; align-items: center; margin-bottom: 1rem;">
                <div>
                    <span class="url-label">Risk Score</span>
                    <div style="font-size: 1.5rem; font-weight: 700;">${scan.scanScore} / 100</div>
                </div>
                <div>
                    <span class="url-label">Classification</span>
                    <div><span class="badge ${badgeClass}">${escapeHtml(scan.scanStatus)}</span></div>
                </div>
                <div>
                    <span class="url-label">Scanned At</span>
                    <div style="font-size: 0.9rem; color: var(--text-secondary);">${escapeHtml(scan.scannedAt || 'N/A')}</div>
                </div>
            </div>

            <div class="url-label">Identified Warning Signs (${findings.length})</div>
            ${findingsHtml}
        `;
    }

    function closeModal() {
        detailsModal.classList.remove('active');
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
});
