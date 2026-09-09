import unittest
from rules.url_analyzer import check_url_concatenation, check_idn_homograph, check_obfuscated_ip

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

if __name__ == '__main__':
    unittest.main()
