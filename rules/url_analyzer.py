import re
import urllib.parse
import tldextract

SHORTENERS = [
    'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'cli.gs', 
    'pic.gd', 'DwarfURL.com', 'ow.ly', 'yfrog.com', 'migre.me', 
    'ff.im', 'tiny.cc', 'url4.eu', 'tr.im', 'twit.ac', 'su.pr', 
    'twurl.nl', 'snipurl.com', 'short.to', 'BudURL.com', 'ping.fm',
    'post.ly', 'Just.as', 'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us',
    'doiop.com', 'short.ie', 'kl.am', 'wp.me', 'rubyurl.com', 'om.ly',
    'to.ly', 'bit.do', 't.co', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly',
    'bitly.com', 'cur.lv', 'tinyarrows.com', 'v.gd', 'q.gs', 'po.st',
    'bc.vc', 'twitthis.com', 'u.to', 'j.mp', 'buzurl.com', 'cutt.us',
    'u.bb', 'yourls.org', 'x.co', 'prettylinkpro.com', 'scrnch.me', 'filoops.info'
]

import json
import os

def load_temporary_hosting_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'temporary_hosting.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f).get('providers', [])
    except Exception:
        return []

TEMPORARY_HOSTING_PROVIDERS = load_temporary_hosting_config()

def check_ip_address(url):
    """Detects if an IP address is used as the domain."""
    domain = urllib.parse.urlparse(url).netloc
    # Regex for IPv4 and IPv6
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    if re.match(ipv4_pattern, domain) or re.match(ipv6_pattern, domain):
        return True
    return False

def check_url_length(url):
    """Detects if the URL is excessively long (over 75 characters)."""
    return len(url) > 75

def check_at_symbol(url):
    """Detects if the URL contains an '@' symbol."""
    return '@' in url

def check_url_shortener(url):
    """Detects if a known URL shortener service is used."""
    domain = urllib.parse.urlparse(url).netloc
    for shortener in SHORTENERS:
        if shortener in domain:
            return True
    return False

def check_excessive_subdomains(url):
    """Detects if there are excessive subdomains (more than 3)."""
    ext = tldextract.extract(url)
    subdomains = ext.subdomain.split('.')
    # Empty string means no subdomain. e.g. ['www'] is 1, [''] is 0.
    count = len([s for s in subdomains if s])
    return count >= 3

def check_hyphenated_domain(url):
    """Returns the number of hyphens in the domain."""
    ext = tldextract.extract(url)
    # Count hyphens in the main domain part
    return ext.domain.count('-')

def check_semantic_keywords(url):
    """Checks if the URL contains common credential-harvesting words."""
    keywords = ['login', 'verify', 'update', 'secure', 'account', 'billing', 'support', 'auth', 'recover']
    url_lower = url.lower()
    count = 0
    for keyword in keywords:
        if keyword in url_lower:
            count += 1
    return count

def check_tunneling_service(url):
    """Detects if the URL is using a known tunneling service often abused for phishing."""
    domain = urllib.parse.urlparse(url).netloc
    for provider in TEMPORARY_HOSTING_PROVIDERS:
        if provider['domain'] in domain:
            return {'detected': True, 'provider': provider['name']}
    return {'detected': False, 'provider': None}

def check_random_subdomain(url):
    """Detects random, generated, or suspicious subdomains."""
    ext = tldextract.extract(url)
    subdomain = ext.subdomain
    if not subdomain:
        return {'random_or_generated': False, 'subdomain': ''}
        
    is_random = False
    if len(subdomain) >= 15 and subdomain.count('-') >= 2:
        is_random = True
    elif re.search(r'\d{5,}', subdomain):
        is_random = True
    elif len(subdomain) > 20 and subdomain.count('.') == 0:
        is_random = True
        
    return {'random_or_generated': is_random, 'subdomain': subdomain}

def check_url_concatenation(url):
    """Detects multiple http:// or https:// in a single string."""
    return len(re.findall(r'https?://', url.lower())) > 1

def check_idn_homograph(url):
    """Detects Punycode or non-ASCII characters in the domain."""
    domain = urllib.parse.urlparse(url).netloc.split(':')[0]
    if domain.startswith('xn--') or 'xn--' in domain:
        return True
    # Check for non-ASCII characters
    if not all(ord(c) < 128 for c in domain):
        return True
    return False

def check_high_risk_tld(url):
    """Flags extensions statistically prone to phishing."""
    high_risk_tlds = ['top', 'xyz', 'pro', 'shop', 'work', 'click', 'biz', 'info']
    ext = tldextract.extract(url)
    return ext.suffix.lower() in high_risk_tlds

def check_non_standard_port(url):
    """Flags URLs using non-default web ports."""
    parsed = urllib.parse.urlparse(url)
    port = parsed.port
    if port and port not in (80, 443):
        return True
    return False

def check_obfuscated_ip(url):
    """Detects DWORD, Hex, Octal IP representations, or zero-width unicode."""
    domain = urllib.parse.urlparse(url).netloc.split(':')[0]
    
    # Zero-width characters
    if re.search(r'[\u200B-\u200D\uFEFF]', domain):
        return True
        
    # Check if domain is entirely numeric (DWORD/Octal) or hex
    # DWORD could be a single huge number
    if re.match(r'^\d+$', domain):
        return True
        
    # Hex IPs like 0x7F000001
    if re.match(r'^0x[a-fA-F0-9]+$', domain):
        return True
        
    # Octal IPs like 0177.0000.0000.0001
    if re.match(r'^(0\d+)(\.0\d+){0,3}$', domain):
        return True
        
    return False

def analyze_url(url):
    """Runs all URL-based checks and returns a dict of boolean results."""
    return {
        'ip_address': check_ip_address(url),
        'url_length': check_url_length(url),
        'at_symbol': check_at_symbol(url),
        'url_shortener': check_url_shortener(url),
        'excessive_subdomains': check_excessive_subdomains(url),
        'hyphenated_domain': check_hyphenated_domain(url),
        'tunneling_info': check_tunneling_service(url),
        'subdomain_info': check_random_subdomain(url),
        'semantic_keyword_count': check_semantic_keywords(url),
        'url_concatenation': check_url_concatenation(url),
        'idn_homograph': check_idn_homograph(url),
        'high_risk_tld': check_high_risk_tld(url),
        'non_standard_port': check_non_standard_port(url),
        'obfuscated_ip': check_obfuscated_ip(url)
    }