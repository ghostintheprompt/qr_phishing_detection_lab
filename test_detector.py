import unittest

from detector import score_url


class URLBoundaryTests(unittest.TestCase):
    def test_platform_and_real_subdomains(self):
        for url in ("https://ebay.com/", "https://www.ebay.com/",
                    "https://checkout.ebay.com:443/", "https://EBAY.COM./"):
            with self.subTest(url=url):
                self.assertEqual(score_url(url)["risk_level"], "low")

    def test_lookalikes_and_userinfo_are_not_platform_hosts(self):
        for url in ("https://ebay.com.attacker.invalid/checkout",
                    "https://notebay.com/", "https://ebay.com@attacker.invalid/",
                    "https://user:password@ebay.com/"):
            with self.subTest(url=url):
                self.assertEqual(score_url(url)["risk_level"], "high")
        self.assertEqual(score_url("https://ebay.com@attacker.invalid/")["host"],
                         "attacker.invalid")

    def test_shortener_with_port_and_original_demo(self):
        for url in ("https://bit.ly:443/example", "https://bit.ly/ebay-release-payment-x92"):
            with self.subTest(url=url):
                result = score_url(url)
                self.assertTrue(any("shortener" in f for f in result["risk_flags"]))
                self.assertEqual(result["risk_level"], "high")

    def test_malformed_missing_and_ambiguous_authorities(self):
        for url in ("https://[broken/", "https://ebay.com:bad/", "https://ebay.com:99999/",
                    "https:///checkout", "http://ebay.com/", "not a URL",
                    "https://user\\@ebay.com/", "https://ebay.com/has space"):
            with self.subTest(url=url):
                self.assertEqual(score_url(url)["risk_level"], "high")


if __name__ == "__main__":
    unittest.main()
