document.addEventListener('DOMContentLoaded', () => {
    // Initial scan history load
    loadHistory();

    // --- Navigation / Tabs Logic ---
    const navItems = document.querySelectorAll('.nav-item');
    const tabPanes = document.querySelectorAll('.tab-pane');

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            // Update active state on nav
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');

            // Switch tab pane
            const targetTab = item.getAttribute('data-tab');
            tabPanes.forEach(pane => {
                if (pane.id === targetTab) {
                    pane.classList.remove('hidden');
                    pane.classList.add('active');
                } else {
                    pane.classList.add('hidden');
                    pane.classList.remove('active');
                }
            });
        });
    });

    // --- Scanner Logic ---
    const scanForm = document.getElementById('scan-form');
    const urlInput = document.getElementById('url-input');
    const scanBtn = document.getElementById('scan-btn');
    const btnText = document.querySelector('.btn-text');
    const spinner = document.querySelector('.spinner');
    const errorMessage = document.getElementById('error-message');
    
    const resultsContainer = document.getElementById('results-container');
    const riskScoreEl = document.getElementById('risk-score');
    const verdictTitle = document.getElementById('verdict-title');
    const verdictDesc = document.getElementById('verdict-desc');
    const scoreRingProgress = document.getElementById('score-ring-progress');
    const verdictCard = document.getElementById('verdict-card');
    
    const urlFeaturesList = document.getElementById('url-features');
    const domainFeaturesList = document.getElementById('domain-features');
    const contentFeaturesList = document.getElementById('content-features');

    const LABELS = {
        'ip_address': 'IP Address as Domain',
        'url_length': 'Excessive URL Length',
        'at_symbol': 'Contains @ Symbol',
        'url_shortener': 'URL Shortener Used',
        'excessive_subdomains': 'Excessive Subdomains',
        'hyphenated_domain': 'Hyphenated Domain',
        'young_domain': 'Domain Registered Recently',
        'whois_anomalies': 'WHOIS Information Hidden/Missing',
        'ssl_issues': 'Invalid/Missing SSL Certificate',
        'insecure_login_form': 'Password Field on Non-HTTPS Page',
        'mismatched_favicon': 'Favicon Domain Mismatch',
        'external_form_target': 'Form Submits to External Domain',
        'hidden_iframes': 'Hidden iFrames Detected',
        'right_click_blocked': 'Right-Click / Inspect Blocked',
        'content_unreachable': 'Page Content Unreachable (Timeout/Blocked)',
        'connection_blocked_by_antivirus': 'Connection Blocked by Endpoint Antivirus',
        'google_safe_browsing_flagged': 'Flagged by Google Safe Browsing',
        'virustotal_flagged': 'Flagged by VirusTotal',
        'tunneling_service': 'Suspicious Tunneling Service / Temporary Hosting',
        'random_subdomain': 'Random / Generated Subdomain',
        'semantic_keywords': 'Credential-Harvesting Semantic Keywords',
        'url_concatenation': 'URL Concatenation / Glued Protocols',
        'idn_homograph': 'IDN Homograph / Punycode',
        'high_risk_tld': 'High-Risk Abuse TLD',
        'non_standard_port': 'Non-Standard Web Port',
        'obfuscated_ip': 'Obfuscated / Encoded IP',
        'free_paas': 'Abuse of Free PaaS / Storage',
        'dynamic_dns': 'Dynamic DNS Provider',
        'missing_mx_records': 'Missing / Invalid MX Records',
        'fast_flux_dns': 'Fast-Flux DNS / Low TTL',
        'decoy_captcha': 'Decoy Captcha / Turnstile Gate',
        'obfuscated_javascript': 'Obfuscated JavaScript / Packer',
        'client_side_redirect': 'Client-Side Redirect',
        'anti_analysis_blocking': 'Anti-Analysis / DevTools Blocking',
        'highly_sensitive_inputs': 'Highly Sensitive Inputs (CVV, SSN, OTP)',
        'cloaking_detected': 'Cloaking / Anti-Bot Mismatch',
        'visual_logo_mismatch': 'Visual Logo Mismatch'
    };

    const CATEGORIES = {
        'ip_address': urlFeaturesList,
        'url_length': urlFeaturesList,
        'at_symbol': urlFeaturesList,
        'url_shortener': urlFeaturesList,
        'excessive_subdomains': urlFeaturesList,
        'hyphenated_domain': urlFeaturesList,
        'young_domain': domainFeaturesList,
        'whois_anomalies': domainFeaturesList,
        'ssl_issues': domainFeaturesList,
        'insecure_login_form': contentFeaturesList,
        'mismatched_favicon': contentFeaturesList,
        'external_form_target': contentFeaturesList,
        'hidden_iframes': contentFeaturesList,
        'right_click_blocked': contentFeaturesList,
        'content_unreachable': contentFeaturesList,
        'connection_blocked_by_antivirus': contentFeaturesList,
        'google_safe_browsing_flagged': domainFeaturesList,
        'virustotal_flagged': domainFeaturesList,
        'tunneling_service': urlFeaturesList,
        'random_subdomain': urlFeaturesList,
        'semantic_keywords': urlFeaturesList,
        'url_concatenation': urlFeaturesList,
        'idn_homograph': urlFeaturesList,
        'high_risk_tld': urlFeaturesList,
        'non_standard_port': urlFeaturesList,
        'obfuscated_ip': urlFeaturesList,
        'free_paas': domainFeaturesList,
        'dynamic_dns': domainFeaturesList,
        'missing_mx_records': domainFeaturesList,
        'fast_flux_dns': domainFeaturesList,
        'decoy_captcha': contentFeaturesList,
        'obfuscated_javascript': contentFeaturesList,
        'client_side_redirect': contentFeaturesList,
        'anti_analysis_blocking': contentFeaturesList,
        'highly_sensitive_inputs': contentFeaturesList,
        'cloaking_detected': contentFeaturesList,
        'visual_logo_mismatch': contentFeaturesList
    };

    let riskChart = null;

    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = urlInput.value.trim();
        if (!url) return;

        // UI Reset & Loading State
        errorMessage.classList.add('hidden');
        if (resultsContainer) resultsContainer.classList.add('hidden');
        btnText.classList.add('hidden');
        spinner.classList.remove('hidden');
        scanBtn.disabled = true;

        if (verdictTitle) verdictTitle.textContent = "Analyzing...";
        if (verdictDesc) verdictDesc.textContent = "Evaluating threat indicators and heuristic models.";
        if (riskScoreEl) riskScoreEl.textContent = "...";
        if (scoreRingProgress) scoreRingProgress.style.strokeDashoffset = 408;

        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Failed to analyze URL.');
            }

            displayResults(data);

        } catch (error) {
            const errorTextSpan = document.getElementById('error-text');
            if(errorTextSpan) {
                errorTextSpan.textContent = error.message;
            } else {
                errorMessage.textContent = error.message;
            }
            errorMessage.classList.remove('hidden');
            if (verdictTitle) verdictTitle.textContent = "Ready";
            if (verdictDesc) verdictDesc.textContent = "Awaiting valid URL to analyze.";
            if (riskScoreEl) riskScoreEl.textContent = "0";
        } finally {
            // Revert Loading State
            btnText.classList.remove('hidden');
            spinner.classList.add('hidden');
            scanBtn.disabled = false;
        }
    });

    function displayResults(data) {
        animateScore(data.score);
        
        verdictTitle.textContent = data.verdict;
        verdictCard.className = 'verdict-card glass-panel';
        
        if (data.verdict === 'Phishing' || data.verdict === 'Critical') {
            verdictCard.classList.add('verdict-phishing');
            verdictDesc.textContent = "Critical threat indicators detected. Do not proceed.";
            scoreRingProgress.style.stroke = "var(--status-phishing)";
        } else if (data.verdict === 'Suspicious') {
            verdictCard.classList.add('verdict-suspicious');
            verdictDesc.textContent = "Multiple risk factors present. Proceed with extreme caution.";
            scoreRingProgress.style.stroke = "var(--status-suspicious)";
        } else {
            verdictCard.classList.add('verdict-legitimate');
            verdictDesc.textContent = "No significant threat indicators detected.";
            scoreRingProgress.style.stroke = "var(--status-safe)";
        }

        // Clear previous lists
        urlFeaturesList.innerHTML = '';
        domainFeaturesList.innerHTML = '';
        contentFeaturesList.innerHTML = '';

        // Populate Explainable Results
        const reasonsList = document.getElementById('reasons-list');
        if (reasonsList) {
            reasonsList.innerHTML = '';
            if (data.reasons && data.reasons.length > 0) {
                data.reasons.forEach(reason => {
                    const isSafeReason = data.score === 0 || /allowlist|whitelist|legitimate|verified/i.test(reason);
                    const iconColor = isSafeReason ? 'var(--threat-low)' : 'var(--threat-high)';
                    const iconSvg = isSafeReason
                        ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: ${iconColor}"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`
                        : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: ${iconColor}"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
                    
                    const li = document.createElement('li');
                    li.innerHTML = `${iconSvg} ${reason}`;
                    reasonsList.appendChild(li);
                });
            } else {
                const li = document.createElement('li');
                li.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--threat-low)"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg> No specific reasons flagged by detailed engine.`;
                reasonsList.appendChild(li);
            }
        }

        const regDomainEl = document.getElementById('detail-registered-domain');
        if (regDomainEl) {
            regDomainEl.textContent = (data.domain_analysis && data.domain_analysis.registered_domain) ? data.domain_analysis.registered_domain : 'Unknown';
            
            let ageStr = 'Unknown';
            if (data.domain_analysis && data.domain_analysis.domain_age_days !== null && data.domain_analysis.domain_age_days !== undefined) {
                ageStr = `${data.domain_analysis.domain_age_days} days old`;
            }
            document.getElementById('detail-domain-age').textContent = ageStr;

            let hostStr = 'No';
            if (data.temporary_hosting && data.temporary_hosting.detected) {
                hostStr = `Yes (${data.temporary_hosting.provider})`;
            }
            document.getElementById('detail-temporary-host').textContent = hostStr;

            let subStr = 'No';
            if (data.subdomain_analysis && data.subdomain_analysis.random_or_generated) {
                subStr = 'Yes';
            }
            document.getElementById('detail-random-subdomain').textContent = subStr;
        }

        // Add dummy entry if nothing triggered
        if (data.triggered_rules.length === 0) {
            const li = document.createElement('li');
            li.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg> No heuristics triggered`;
            urlFeaturesList.appendChild(li);
        }

        // Populate triggered heuristics
        for (const ruleItem of data.triggered_rules) {
            // Handle both new detailed object format and old string format
            const ruleName = (typeof ruleItem === 'object') ? ruleItem.rule_name : ruleItem;
            const description = (typeof ruleItem === 'object') ? ruleItem.description : '';
            
            const list = CATEGORIES[ruleName];
            if (!list) continue;
            
            const li = document.createElement('li');
            li.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--threat-high)"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg> 
            <div>
                <strong>${LABELS[ruleName] || ruleName}</strong>
                ${description ? `<p style="margin: 2px 0 0 0; font-size: 0.85em; color: var(--text-tertiary);">${description}</p>` : ''}
            </div>`;
            li.style.display = 'flex';
            li.style.gap = '8px';
            li.style.alignItems = 'flex-start';
            list.appendChild(li);
        }

        renderChart(data.category_scores);
        if (resultsContainer) resultsContainer.classList.remove('hidden');
        loadHistory();
    }

    function renderChart(categoryScores) {
        const ctx = document.getElementById('riskChart').getContext('2d');
        
        if (riskChart) {
            riskChart.destroy();
        }

        const data = [
            categoryScores.url || 0,
            categoryScores.domain || 0,
            categoryScores.content || 0
        ];

        // If score is 0, still show a tiny sliver so the chart exists
        const displayData = data.map(val => val === 0 ? 2 : val);

        riskChart = new Chart(ctx, {
            type: 'polarArea',
            data: {
                labels: ['URL Architecture Risk', 'Domain & Reputation Risk', 'Content Integrity Risk'],
                datasets: [{
                    label: 'Risk Score Allocation',
                    data: displayData,
                    backgroundColor: [
                        'rgba(119, 153, 85, 0.75)',   // Asparagus Green
                        'rgba(143, 188, 143, 0.75)',  // Dark Sea Green
                        'rgba(172, 225, 175, 0.75)'   // Celadon
                    ],
                    borderColor: [
                        'rgba(85, 117, 53, 1)',       // Asparagus Deep
                        'rgba(63, 110, 77, 1)',       // Dark Sea Green Deep
                        'rgba(115, 179, 120, 1)'      // Celadon Deep
                    ],
                    borderWidth: 1.5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        ticks: { display: false, max: 100 },
                        grid: { color: 'rgba(143, 188, 143, 0.28)' },
                        angleLines: { color: 'rgba(143, 188, 143, 0.28)' }
                    }
                },
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#18311e', // Deep Forest Asparagus for light theme
                            font: {
                                family: 'Inter',
                                size: 12,
                                weight: '600'
                            }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                // Show original value instead of sliver value
                                return context.label + ': ' + data[context.dataIndex] + ' pts';
                            }
                        }
                    }
                }
            }
        });
    }

    function animateScore(score) {
        let current = 0;
        const duration = 1000;
        const stepTime = Math.abs(Math.floor(duration / (score || 1)));
        
        riskScoreEl.textContent = "0";
        
        // Calculate offset (408 is max for r=65)
        const maxOffset = 408;
        const offset = maxOffset - (maxOffset * (score / 100));
        
        // Use a slight timeout to ensure CSS transition triggers
        setTimeout(() => {
            scoreRingProgress.style.strokeDashoffset = offset;
        }, 50);

        if (score === 0) return;

        const timer = setInterval(() => {
            current += 1;
            riskScoreEl.textContent = current;
            if (current >= score) {
                clearInterval(timer);
            }
        }, stepTime);
    }

    // --- History Logic ---
    async function loadHistory() {
        const bodies = document.querySelectorAll('.history-body-container');
        if (bodies.length === 0) {
            const single = document.getElementById('history-body');
            if (single) single.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 2rem; color: var(--text-tertiary);">Loading history...</td></tr>';
        } else {
            bodies.forEach(b => {
                b.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 2rem; color: var(--text-tertiary);">Loading history...</td></tr>';
            });
        }
        
        try {
            const response = await fetch('/api/history');
            const history = await response.json();
            
            const targetBodies = bodies.length > 0 ? Array.from(bodies) : [document.getElementById('history-body')].filter(Boolean);

            if (history.length === 0) {
                targetBodies.forEach(b => {
                    b.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 2rem; color: var(--text-tertiary);">No scans performed yet.</td></tr>';
                });
                return;
            }
            
            targetBodies.forEach(b => {
                b.innerHTML = '';
                history.forEach(scan => {
                    const tr = document.createElement('tr');
                    
                    let verdictBadge = '';
                    if (scan.verdict === 'Phishing' || scan.verdict === 'Critical') {
                        verdictBadge = '<span class="badge badge-critical">Phishing</span>';
                    } else if (scan.verdict === 'Suspicious') {
                        verdictBadge = '<span class="badge badge-med">Suspicious</span>';
                    } else {
                        verdictBadge = '<span class="badge badge-low">Legitimate</span>';
                    }

                    tr.innerHTML = `
                        <td class="timestamp-cell">${scan.timestamp}</td>
                        <td class="url-cell" title="${scan.url}">${scan.url}</td>
                        <td class="score-cell">${scan.score}</td>
                        <td>${verdictBadge}</td>
                    `;
                    b.appendChild(tr);
                });
            });
            
        } catch (error) {
            console.error('Failed to load history:', error);
            const targetBodies = bodies.length > 0 ? Array.from(bodies) : [document.getElementById('history-body')].filter(Boolean);
            targetBodies.forEach(b => {
                b.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 2rem; color: var(--status-phishing);">Failed to load history.</td></tr>';
            });
        }
    }

    // --- "Why it get flagged" Modal Logic ---
    const detailsModal = document.getElementById('details-modal');
    const closeModalBtn = document.getElementById('close-modal-btn');
    const btnWhyFlagged = document.getElementById('btn-why-flagged');
    const btnWhyFlaggedTable = document.getElementById('btn-why-flagged-table');

    function openDetailsModal() {
        if (!detailsModal) return;
        detailsModal.classList.add('active');
        if (riskChart) {
            setTimeout(() => {
                riskChart.resize();
            }, 50);
        }
    }

    function closeDetailsModal() {
        if (!detailsModal) return;
        detailsModal.classList.remove('active');
    }

    if (btnWhyFlagged) {
        btnWhyFlagged.addEventListener('click', openDetailsModal);
    }
    if (btnWhyFlaggedTable) {
        btnWhyFlaggedTable.addEventListener('click', openDetailsModal);
    }
    if (closeModalBtn) {
        closeModalBtn.addEventListener('click', closeDetailsModal);
    }
    if (detailsModal) {
        detailsModal.addEventListener('click', (e) => {
            if (e.target === detailsModal) {
                closeDetailsModal();
            }
        });
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && detailsModal.classList.contains('active')) {
                closeDetailsModal();
            }
        });
    }
});
