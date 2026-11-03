#!/usr/bin/env python3
"""
Unit tests for Multi-Cloud SOAR Remediation Engine CLI
Author: Luis García Villena
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from multicloud_soar_engine import MultiCloudSoarEngine


class TestMultiCloudSoarEngine(unittest.TestCase):

    def setUp(self):
        self.engine_dry = MultiCloudSoarEngine(dry_run=True)
        self.engine_live = MultiCloudSoarEngine(dry_run=False)

    def test_parse_guardduty_alert(self):
        alert_payload = json.dumps({
            "schemaVersion": "2.0",
            "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
            "severity": 8.0,
            "region": "eu-west-1",
            "resource": {
                "instanceDetails": {"instanceId": "i-1234567890abcdef0"}
            }
        })
        parsed = self.engine_dry.parse_alert(alert_payload)
        self.assertEqual(parsed["source_siem"], "AWS GuardDuty")
        self.assertEqual(parsed["severity"], "CRITICAL")
        self.assertEqual(parsed["target_resource"]["id"], "i-1234567890abcdef0")
        self.assertEqual(parsed["target_resource"]["type"], "compute")

    def test_parse_sentinel_alert(self):
        alert_payload = json.dumps({
            "IncidentNumber": 501,
            "AlertName": "Privilege Escalation in Azure AD",
            "Severity": "High",
            "Entities": [
                {"Type": "account", "AccountName": "admin@contoso.com"}
            ]
        })
        parsed = self.engine_dry.parse_alert(alert_payload)
        self.assertEqual(parsed["source_siem"], "Microsoft Sentinel")
        self.assertEqual(parsed["severity"], "HIGH")
        self.assertEqual(parsed["target_resource"]["id"], "admin@contoso.com")
        self.assertEqual(parsed["target_resource"]["type"], "iam")

    def test_execute_compute_isolation_dry_run(self):
        target = {"id": "i-test-001", "type": "compute", "provider": "aws"}
        res = self.engine_dry.execute_playbook("PLAYBOOK-ISO-COMPUTE", target)
        self.assertEqual(res["mode"], "DRY_RUN")
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["actions_executed"], 2)
        self.assertEqual(res["action_log"][0]["status"], "SIMULATED_SUCCESS")

    def test_execute_iam_revocation_live(self):
        target = {"id": "AKIA-COMPROMISED", "type": "iam", "provider": "aws"}
        res = self.engine_live.execute_playbook("PLAYBOOK-REVOKE-IAM", target)
        self.assertEqual(res["mode"], "LIVE_REMEDIATION")
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["action_log"][0]["status"], "EXECUTED")

    def test_invalid_playbook(self):
        with self.assertRaises(KeyError):
            self.engine_dry.execute_playbook("INVALID-PLAYBOOK-XYZ", {"id": "none"})

    def test_list_playbooks(self):
        pbs = self.engine_dry.list_playbooks()
        self.assertEqual(len(pbs), 4)
        pb_ids = [p["playbook_id"] for p in pbs]
        self.assertIn("PLAYBOOK-ISO-COMPUTE", pb_ids)
        self.assertIn("PLAYBOOK-REVOKE-IAM", pb_ids)
        self.assertIn("PLAYBOOK-BLOCK-STORAGE", pb_ids)
        self.assertIn("PLAYBOOK-FORENSIC-SNAPSHOT", pb_ids)


if __name__ == "__main__":
    unittest.main()
