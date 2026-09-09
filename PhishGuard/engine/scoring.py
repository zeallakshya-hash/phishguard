from rules.url_analyzer import analyze_url
from rules.domain_analyzer import analyze_domain, get_domain
from rules.content_analyzer import analyze_content
from rules.api_analyzer import analyze_api
from rules.cloaking_analyzer import analyze_cloaking

# Define risk weights for each heuristic
WEIGHTS = {
    # URL Features
    'ip_address': 30,
    'url_length': 5,
    'at_symbol': 15,
    'url_shortener': 10,
    'excessive_subdomains': 15,
    'url_concatenation': 25,
    'idn_homograph': 30,
    'high_risk_tld': 15,
    'non_standard_port': 15,
    'obfuscated_ip': 20,
    
    # Domain Features
    'young_domain': 25,
    'whois_anomalies': 15,
    'ssl_issues': 25,
    'free_paas': 20,
    'dynamic_dns': 20,
    'missing_mx_records': 10,
    'fast_flux_dns': 20,
    
    # Content Features
    'insecure_login_form': 35,
    'mismatched_favicon': 10,
    'external_form_target': 30,
    'hidden_iframes': 20,
    'right_click_blocked': 15,
    'content_unreachable': 15, # Treat unreachable as suspicious, but don't flag as phishing just for this
    'connection_blocked_by_antivirus': 100,
    'decoy_captcha': 25,
    'obfuscated_javascript': 20,
    'client_side_redirect': 15,
    'anti_analysis_blocking': 15,
    'highly_sensitive_inputs': 35,
    
    # Cloaking Features
    'cloaking_detected': 30,
    'visual_logo_mismatch': 35,
    
    # API Blacklists
    'google_safe_browsing_flagged': 100,
    'phishtank_flagged': 100,
    'virustotal_flagged': 100
}

def calculate_score(url):
    """
    Evaluates the URL across all analyzers, calculates a weighted risk score,
    and returns a verdict along with the breakdown.
    """
    import urllib.parse
    domain = urllib.parse.urlparse(url).netloc.lower()
    
    # Whitelist trusted domains (like our own hosting)
    if domain in ["phishguard-pearl.vercel.app", "127.0.0.1:5000", "localhost:5000"]:
        return {
            'total_score': 0,
            'risk_level': 'Low',
            'triggered_rules': [],
            'url': url,
            'score': 0,
            'category_scores': {'url': 0, 'domain': 0, 'content': 0},
            'verdict': 'Legitimate',
            'details': {},
            'risk_score': 0,
            'classification': 'SAFE',
            'domain_analysis': {
                'hostname': domain,
                'registered_domain': domain,
                'domain_age_days': None,
                'domain_age_status': 'UNKNOWN',
                'risk_points': 0
            },
            'temporary_hosting': {
                'detected': False,
                'provider': None,
                'risk_points': 0
            },
            'subdomain_analysis': {
                'subdomain': '',
                'random_or_generated': False,
                'risk_points': 0
            },
            'reasons': ["Domain is explicitly whitelisted."],
            'simple_triggered_rules': []
        }
    
    # Run all analyzers
    url_results = analyze_url(url)
    domain_results = analyze_domain(url)
    content_results = analyze_content(url)
    api_results = analyze_api(url)
    cloaking_results = analyze_cloaking(url)
    
    # Check urlhaus if it exists in url_analyzer (user added it)
    from rules.url_analyzer import check_urlhaus
    urlhaus_result = check_urlhaus(url)
    if urlhaus_result.get('status') == 'Phishing/Malware':
        api_results['urlhaus_flagged'] = True
    else:
        api_results['urlhaus_flagged'] = False

    # Extract the new detailed dicts so they don't break the boolean loop
    domain_age_info = domain_results.pop('domain_age_info', {})
    tunneling_info = url_results.pop('tunneling_info', {})
    subdomain_info = url_results.pop('subdomain_info', {})
    hyphen_count = url_results.pop('hyphenated_domain', 0)
    semantic_keyword_count = url_results.pop('semantic_keyword_count', 0)

    # Combine boolean results
    all_results = {**url_results, **domain_results, **content_results, **api_results, **cloaking_results}
    
    total_score = 0
    category_scores = {
        'url': 0,
        'domain': 0,
        'content': 0
    }
    triggered_rules = []
    # Helper to append detailed rule object
    def add_triggered_rule(rule_name, score_added, description):
        triggered_rules.append({
            'rule_name': rule_name,
            'score_added': score_added,
            'description': description
        })
        
    reasons = []
    
    # Calculate score for boolean rules
    for rule, is_triggered in all_results.items():
        if is_triggered:
            weight = WEIGHTS.get(rule, 0)
            if rule == 'urlhaus_flagged':
                weight = 100
                
            total_score += weight
            add_triggered_rule(rule, weight, f"Triggered check for {rule.replace('_', ' ').title()}")
            reasons.append(f"Triggered check for {rule.replace('_', ' ').title()}")
            
            # Add to category
            if rule in url_results or rule == 'urlhaus_flagged':
                category_scores['url'] += weight
            elif rule in domain_results or rule in ['google_safe_browsing_flagged', 'phishtank_flagged', 'virustotal_flagged']:
                category_scores['domain'] += weight
            elif rule in content_results or rule in cloaking_results:
                category_scores['content'] += weight
                
    # Process Domain Age
    age_points = 0
    age_status = domain_age_info.get('status', 'UNKNOWN')
    age_days = domain_age_info.get('days')
    if age_days is not None:
        if age_days < 7:
            age_points = 25
            reasons.append(f"Domain registered recently: {age_days} days old")
        elif age_days < 30:
            age_points = 15
            reasons.append(f"Domain registered recently: {age_days} days old")
        elif age_days < 90:
            age_points = 10
            reasons.append(f"Domain registered recently: {age_days} days old")
            
        if age_points > 0:
            total_score += age_points
            category_scores['domain'] += age_points
            add_triggered_rule('young_domain', age_points, f"Domain registered recently: {age_days} days old")
            
    # Process Temporary Hosting
    tunnel_points = 0
    if tunneling_info.get('detected'):
        tunnel_points = 15
        total_score += tunnel_points
        category_scores['url'] += tunnel_points
        add_triggered_rule('tunneling_service', tunnel_points, f"Temporary tunnel hosting detected: {tunneling_info.get('provider')}")
        reasons.append(f"Temporary tunnel hosting detected: {tunneling_info.get('provider')}")
        
    # Process Random Subdomain
    subdomain_points = 0
    if subdomain_info.get('random_or_generated'):
        subdomain_points = 10
        total_score += subdomain_points
        category_scores['url'] += subdomain_points
        add_triggered_rule('random_subdomain', subdomain_points, "Random/generated subdomain detected")
        reasons.append("Random/generated subdomain detected")
        
    # Process Semantic Keywords
    keyword_points = 0
    if semantic_keyword_count > 0:
        keyword_points = semantic_keyword_count * 10
        total_score += keyword_points
        category_scores['url'] += keyword_points
        add_triggered_rule('semantic_keywords', keyword_points, f"Suspicious semantic keywords found: {semantic_keyword_count} keyword(s)")
        reasons.append(f"Suspicious semantic keywords found: {semantic_keyword_count} keyword(s)")
        
    # Process Hyphenated Domain
    if hyphen_count >= 2:
        total_score += 10
        category_scores['url'] += 10
        add_triggered_rule('hyphenated_domain', 10, "Multiple hyphens detected in domain")
        reasons.append("Multiple hyphens detected in domain")
    elif hyphen_count == 1:
        if age_days is not None and age_days < 90:
            total_score += 10
            category_scores['url'] += 10
            add_triggered_rule('hyphenated_domain', 10, "Single hyphen in newly registered domain (Correlation Rule)")
            reasons.append("Single hyphen in newly registered domain (Correlation Rule)")
            
    # Normalize score (cap at 100)
    normalized_score = min(total_score, 100)
    
    # Determine verdict & classification
    if normalized_score >= 80:
        verdict = 'Critical'
        classification = 'CRITICAL'
        risk_level = 'Critical'
    elif normalized_score >= 60:
        verdict = 'Phishing'
        classification = 'PHISHING'
        risk_level = 'High'
    elif normalized_score >= 30:
        verdict = 'Suspicious'
        classification = 'SUSPICIOUS'
        risk_level = 'Medium'
    else:
        verdict = 'Legitimate'
        classification = 'SAFE'
        risk_level = 'Low'
        
    import urllib.parse
    
    # Backwards compatible rule list for UI if needed:
    simple_triggered_rules = [r['rule_name'] for r in triggered_rules]
    
    return {
        # ---- New Required JSON Format ----
        'total_score': total_score,  # Raw score requested
        'risk_level': risk_level,
        'triggered_rules': triggered_rules,
        
        # ---- Backward Compatibility for Existing UI ----
        'url': url,
        'score': normalized_score,  # Normalized score
        'category_scores': category_scores,
        'verdict': verdict,
        'details': all_results,
        'risk_score': normalized_score,
        'classification': classification,
        'domain_analysis': {
            'hostname': urllib.parse.urlparse(url).netloc,
            'registered_domain': get_domain(url),
            'domain_age_days': age_days,
            'domain_age_status': age_status,
            'risk_points': age_points
        },
        'temporary_hosting': {
            'detected': tunneling_info.get('detected', False),
            'provider': tunneling_info.get('provider'),
            'risk_points': tunnel_points
        },
        'subdomain_analysis': {
            'subdomain': subdomain_info.get('subdomain', ''),
            'random_or_generated': subdomain_info.get('random_or_generated', False),
            'risk_points': subdomain_points
        },
        'reasons': reasons,
        # 'simple_triggered_rules' helps UI that expected a list of strings
        'simple_triggered_rules': simple_triggered_rules
    }
