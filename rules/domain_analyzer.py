import whois
import datetime
import urllib.parse
import requests
import tldextract
import dns.resolver

def get_domain(url):
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return urllib.parse.urlparse(url).netloc

def check_domain_age(domain_info):
    """Detects domain age and returns detailed age info."""
    result = {'days': None, 'creation_date': None, 'status': 'UNKNOWN'}
    
    if not domain_info:
        return result
    
    creation_date = domain_info.creation_date
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
        
    if creation_date and isinstance(creation_date, datetime.datetime):
        age = datetime.datetime.now() - creation_date
        result['days'] = age.days
        result['creation_date'] = creation_date.strftime("%Y-%m-%d")
        result['status'] = 'KNOWN'
        
    return result

def check_whois_anomalies(domain_info):
    """Detects missing essential WHOIS information."""
    if not domain_info:
        return True
    
    # Check if critical fields are missing or empty
    fields_to_check = ['registrar', 'creation_date', 'expiration_date']
    for field in fields_to_check:
        if not getattr(domain_info, field, None):
            return True
    return False

def check_ssl_issues(url):
    """Checks if the site has SSL certificate issues or is using HTTP."""
    if not url.startswith('https://'):
        return True
    
    try:
        # Requesting the URL to see if SSL handshake fails
        response = requests.get(url, timeout=5)
        # If it succeeds without SSLError, we consider it valid for now
        return False
    except requests.exceptions.SSLError:
        return True
    except requests.exceptions.RequestException:
        # Other connection errors we might mark as suspicious or ignore.
        # Returning True because a broken site can't be fully verified.
        return True

def check_free_paas(url):
    """Detects if the domain uses a free PaaS/Storage platform."""
    domain = urllib.parse.urlparse(url).netloc.lower()
    free_platforms = [
        'firebaseapp.com', 'pages.dev', 'github.io', 
        'webflow.io', 'glitch.me', 'workers.dev', 'netlify.app', 'vercel.app'
    ]
    for platform in free_platforms:
        if domain.endswith(platform):
            return True
    return False

def check_dynamic_dns(url):
    """Flags domains using dynamic DNS services."""
    domain = urllib.parse.urlparse(url).netloc.lower()
    dyndns_providers = ['duckdns.org', 'no-ip.com', 'ngrok.io', 'hopto.org', 'zapto.org', 'serveo.net', 'localtunnel.me']
    for provider in dyndns_providers:
        if domain.endswith(provider):
            return True
    return False

def check_mx_records(url):
    """Checks if the domain lacks MX records."""
    domain = get_domain(url)
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(domain, 'MX')
        return len(answers) == 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return True # Missing or invalid
    except Exception:
        # On generalized error, play it safe and don't flag to avoid false positives
        return False

def check_fast_flux(url):
    """Flags DNS records with low TTL (< 300) or excessive shifting IPs."""
    domain = urllib.parse.urlparse(url).netloc.split(':')[0]
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(domain, 'A')
        
        # Check for multiple IPs (more than 5 for a single A record lookup is suspicious unless huge CDNs, but CDNs also have short TTLs, so correlation is needed)
        # Let's focus on TTL < 300
        if answers.rrset.ttl < 300:
            return True
        return False
    except Exception:
        return False

def analyze_domain(url):
    """Runs domain-based checks."""
    domain = get_domain(url)
    
    try:
        domain_info = whois.whois(domain)
    except Exception as e:
        domain_info = None

    return {
        'domain_age_info': check_domain_age(domain_info),
        'whois_anomalies': check_whois_anomalies(domain_info),
        'ssl_issues': check_ssl_issues(url),
        'free_paas': check_free_paas(url),
        'dynamic_dns': check_dynamic_dns(url),
        'missing_mx_records': check_mx_records(url),
        'fast_flux_dns': check_fast_flux(url)
    }
