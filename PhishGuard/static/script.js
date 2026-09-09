document.addEventListener('DOMContentLoaded', () => {
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

            // Special handling for history tab
            if (targetTab === 'tab-history') {
                loadHistory();
            }
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
        'phishtank_flagged': 'Flagged by PhishTank',
        'virustotal_flagged': 'Flagged by VirusTotal',
        'urlhaus_flagged': 'Flagged by URLhaus Database',
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
        'phishtank_flagged': domainFeaturesList,
        'virustotal_flagged': domainFeaturesList,
        'urlhaus_flagged': urlFeaturesList,
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
        resultsContainer.classList.add('hidden');
        btnText.classList.add('hidden');
        spinner.classList.remove('hidden');
        scanBtn.disabled = true;

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
            scoreRingProgress.style.stroke = "var(--threat-high)";
        } else if (data.verdict === 'Suspicious') {
            verdictCard.classList.add('verdict-suspicious');
            verdictDesc.textContent = "Multiple risk factors present. Proceed with extreme caution.";
            scoreRingProgress.style.stroke = "var(--threat-med)";
        } else {
            verdictCard.classList.add('verdict-legitimate');
            verdictDesc.textContent = "No significant threat indicators detected.";
            scoreRingProgress.style.stroke = "var(--threat-low)";
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
                    const li = document.createElement('li');
                    li.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--threat-high)"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg> ${reason}`;
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
        resultsContainer.classList.remove('hidden');
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
                        'rgba(59, 130, 246, 0.6)',  // Blue
                        'rgba(139, 92, 246, 0.6)',  // Purple
                        'rgba(236, 72, 153, 0.6)'   // Pink
                    ],
                    borderColor: [
                        'rgba(59, 130, 246, 1)',
                        'rgba(139, 92, 246, 1)',
                        'rgba(236, 72, 153, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        ticks: { display: false, max: 100 },
                        grid: { color: 'rgba(255, 255, 255, 0.1)' },
                        angleLines: { color: 'rgba(255, 255, 255, 0.1)' }
                    }
                },
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#94a3b8',
                            font: {
                                family: 'Inter'
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
        const tbody = document.getElementById('history-body');
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 2rem; color: var(--text-tertiary);">Loading history...</td></tr>';
        
        try {
            const response = await fetch('/api/history');
            const history = await response.json();
            
            if (history.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 2rem; color: var(--text-tertiary);">No scans performed yet.</td></tr>';
                return;
            }
            
            tbody.innerHTML = '';
            history.forEach(scan => {
                const tr = document.createElement('tr');
                
                let verdictBadge = '';
                if (scan.verdict === 'Phishing') {
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
                tbody.appendChild(tr);
            });
            
        } catch (error) {
            console.error('Failed to load history:', error);
            tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 2rem; color: var(--threat-high);">Failed to load history.</td></tr>';
        }
    }
});
