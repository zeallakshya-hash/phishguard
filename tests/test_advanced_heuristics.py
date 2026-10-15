import unittest
from unittest.mock import patch
from rules.url_analyzer import (
    check_url_concatenation,
    check_idn_homograph,
    check_obfuscated_ip,
    check_tunneling_service
)
from engine.scoring import calculate_score

class TestAdvancedURLHeuristics(unittest.TestCase):
    
    def test_url_concatenation(self):
        # Valid URLs (should return False)
        self.assertFalse(check_url_concatenation("https://google.com/path/to/resource"))
        self.assertFalse(check_url_concatenation("http://example.com"))
        
        # Concatenated URLs (should return True)
        self.assertTrue(check_url_concatenation("https://example.com/redirect?url=https://malicious.com"))
        self.assertTrue(check_url_concatenation("http://domainA.com/pathhttp://domainB.com"))
        self.assertTrue(check_url_concatenation("https://legit.com@https://phish.com"))

    def test_idn_homograph(self):
        # Valid ASCII domains
        self.assertFalse(check_idn_homograph("https://google.com"))
        self.assertFalse(check_idn_homograph("http://paypal.com/login"))
        
        # Punycode domains
        self.assertTrue(check_idn_homograph("https://xn--pple-43d.com"))
        self.assertTrue(check_idn_homograph("http://login.xn--pypal-4qa.com"))
        
        # Cyrillic/homograph direct characters
        self.assertTrue(check_idn_homograph("https://p\u0430ypal.com")) # Cyrillic 'a'
        self.assertTrue(check_idn_homograph("https://\u0430pple.com")) # Cyrillic 'a'

    def test_obfuscated_ip(self):
        # Valid IP and Domains
        self.assertFalse(check_obfuscated_ip("https://192.168.1.1")) # Standard IP, not obfuscated
        self.assertFalse(check_obfuscated_ip("https://google.com"))
        
        # DWORD IP
        self.assertTrue(check_obfuscated_ip("http://3232235521"))
        
        # Hex IP
        self.assertTrue(check_obfuscated_ip("http://0x7F000001"))
        self.assertTrue(check_obfuscated_ip("http://0xc0a80101"))
        
        # Octal IP
        self.assertTrue(check_obfuscated_ip("http://0177.0000.0000.0001"))
        self.assertTrue(check_obfuscated_ip("http://0300.0250.0001.0001"))
        
        # Zero-width unicode
        self.assertTrue(check_obfuscated_ip("https://google\u200B.com"))
        self.assertTrue(check_obfuscated_ip("https://pay\u200Cpal.com"))

    def test_check_tunneling_service(self):
        # Known tunneling services
        res_cf = check_tunneling_service("https://subdomain.trycloudflare.com/path")
        self.assertTrue(res_cf['detected'])
        self.assertEqual(res_cf['provider'], "Cloudflare Quick Tunnel")

        res_ngrok = check_tunneling_service("http://xyz.ngrok-free.app/login")
        self.assertTrue(res_ngrok['detected'])
        self.assertEqual(res_ngrok['provider'], "Ngrok Free")

        res_localtunnel = check_tunneling_service("https://demo.loca.lt")
        self.assertTrue(res_localtunnel['detected'])
        self.assertEqual(res_localtunnel['provider'], "Localtunnel")

        # Legitimate / non-tunnel URLs
        res_legit = check_tunneling_service("https://google.com")
        self.assertFalse(res_legit['detected'])
        self.assertIsNone(res_legit['provider'])

    @patch('engine.scoring.analyze_cloaking', return_value={})
    @patch('engine.scoring.analyze_content', return_value={})
    @patch('engine.scoring.analyze_domain', return_value={'domain_age_info': {}})
    @patch('engine.scoring.analyze_api', return_value={'google_safe_browsing_flagged': False, 'virustotal_flagged': False})
    def test_tunneling_scoring_points(self, mock_api, mock_domain, mock_content, mock_cloaking):
        result = calculate_score("https://test-host.trycloudflare.com")
        self.assertEqual(result['temporary_hosting']['risk_points'], 30)
        self.assertTrue(result['temporary_hosting']['detected'])
        self.assertGreaterEqual(result['score'], 30)
        self.assertEqual(result['verdict'], 'Suspicious')
        tunnel_rule = next((r for r in result['triggered_rules'] if r['rule_name'] == 'tunneling_service'), None)
        self.assertIsNotNone(tunnel_rule)
        self.assertEqual(tunnel_rule['score_added'], 30)

if __name__ == '__main__':
    unittest.main()

