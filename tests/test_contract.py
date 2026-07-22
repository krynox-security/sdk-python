import json
import pathlib
import unittest
from unittest.mock import patch

from krynox_captcha import KrynoxCaptcha


class GoldenContractTest(unittest.TestCase):
    def test_v1_contract_mapping(self):
        fixture = pathlib.Path(__file__).with_name("fixtures") / "golden-v1.json"
        golden = json.loads(fixture.read_text(encoding="utf-8"))
        client = KrynoxCaptcha("kcps_test", retries=0)
        with patch.object(client, "_post", side_effect=[golden["verify"], golden["classify"]]):
            verified = client.verify("token")
            self.assertTrue(verified.success)
            self.assertEqual(verified.action, "signup")
            self.assertEqual(verified.cdata, "order-42")
            classified = client.classify(text="hello", ip="203.0.113.5")
            self.assertEqual(classified.classification, "NEUTRAL")
            self.assertFalse(classified.blocked)


if __name__ == "__main__":
    unittest.main()
