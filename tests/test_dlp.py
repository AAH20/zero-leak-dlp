import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from zeroleak.core import ZeroLeakDLP, GENESIS_HASH


class TestZeroLeakDLP(unittest.TestCase):
    def setUp(self):
        self.dlp = ZeroLeakDLP()

    def test_secret_interception_and_blocking(self):
        # Raw OpenAI API key leak attempt
        payload = {
            'action': 'post_update',
            'api_token': 'sk-proj-9999888877776666555544443333222211110000',
        }
        allowed, _, receipt = self.dlp.inspect_and_sanitize('send_webhook', payload)
        self.assertFalse(allowed)
        self.assertEqual(receipt.status, 'QUARANTINED_SECRET_EXFILTRATION_ATTEMPT')
        self.assertGreater(receipt.secrets_detected, 0)

    def test_encoded_base64_secret_interception(self):
        # Covert Base64 encoded AWS secret key inside innocuous parameter
        # AKIA1234567890ABCDEF -> QUtJQTEyMzQ1Njc4OTBBQkNERUY=
        payload = {
            'metadata': 'QUtJQTEyMzQ1Njc4OTBBQkNERUY=',
        }
        allowed, _, receipt = self.dlp.inspect_and_sanitize('sync_cloud', payload)
        self.assertFalse(allowed)
        self.assertEqual(receipt.status, 'QUARANTINED_SECRET_EXFILTRATION_ATTEMPT')

    def test_pii_redaction_and_ledger_integrity(self):
        payload = {
            'user_name': 'John Doe',
            'user_email': 'john.doe@example.com',
            'ssn': '123-45-6789',
        }
        allowed, sanitized, receipt = self.dlp.inspect_and_sanitize('update_crm', payload, redact_pii=True)
        self.assertTrue(allowed)
        self.assertEqual(sanitized['user_email'], '[REDACTED_EMAIL]')
        self.assertEqual(sanitized['ssn'], '[REDACTED_SSN]')
        self.assertEqual(receipt.pii_redacted, 2)
        self.assertNotEqual(receipt.signature_hash, GENESIS_HASH)

        # Verify cryptographic chain
        is_valid, err = self.dlp.ledger.verify_chain_integrity()
        self.assertTrue(is_valid, f'DLP ledger broken: {err}')


if __name__ == '__main__':
    unittest.main()
