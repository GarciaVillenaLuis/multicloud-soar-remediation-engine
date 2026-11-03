# Autonomous Multi-Cloud SOAR Remediation Engine ⚡🛡️

[![CI/CD Pipeline](https://github.com/GarciaVillenaLuis/multicloud-soar-remediation-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/GarciaVillenaLuis/multicloud-soar-remediation-engine/actions/workflows/ci.yml)
[![CodeQL](https://github.com/GarciaVillenaLuis/multicloud-soar-remediation-engine/actions/workflows/codeql.yml/badge.svg)](https://github.com/GarciaVillenaLuis/multicloud-soar-remediation-engine/actions/workflows/codeql.yml)
[![SOAR Automation](https://img.shields.io/badge/SOAR-Autonomous%20Incident%20Response-success?style=flat-square&logo=shield&logoColor=white)](https://github.com/GarciaVillenaLuis/multicloud-soar-remediation-engine)
[![Framework](https://img.shields.io/badge/Defense-MITRE%20D3FEND-red?style=flat-square&logo=target&logoColor=white)](https://d3fend.mitre.org/)
[![NIST Compliance](https://img.shields.io/badge/Security-NIST%20SP%20800--61%20Rev%202-orange?style=flat-square)](https://csrc.nist.gov/)
[![Multi-Cloud](https://img.shields.io/badge/Cloud-AWS%20%7C%20Azure%20%7C%20GCP-blue?style=flat-square&logo=googlecloud&logoColor=white)](https://aws.amazon.com/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green?style=flat-square)](LICENSE)

Autonomous, multi-cloud **Security Orchestration, Automation, and Response (SOAR)** CLI engine executing policy-driven containment playbooks, identity revocations, and forensic snapshots across **Amazon Web Services (AWS)**, **Microsoft Azure**, and **Google Cloud Platform (GCP)**.

Developed and maintained by **Luis García Villena** (*Security Transformation Analyst @ Accenture | CCSP® & CCGP ISMS Forum*).

---

## 🌟 Automated Containment Playbooks

- **Compute Instance Isolation (`PLAYBOOK-ISO-COMPUTE`)**:
  - Maps to MITRE D3FEND **D3-NPA** (*Network Policed Access*).
  - Automatically swaps Security Groups / Network Security Groups (NSGs) on compromised virtual machines (EC2, Azure VM, GCE) to an emergency isolation profile blocking all ingress/egress while allowing forensic SSH/RDP from secured bastion hosts.
- **Compromised Identity Revocation (`PLAYBOOK-REVOKE-IAM`)**:
  - Maps to MITRE D3FEND **D3-IAA** (*Invalidate Active Access*).
  - Invalidates active AWS IAM STS tokens, revokes Azure AD refresh tokens, and attaches emergency deny-all permission boundaries.
- **Cloud Storage Bucket Quarantine (`PLAYBOOK-BLOCK-STORAGE`)**:
  - Maps to MITRE D3FEND **D3-ACR** (*Access Control Restriction*).
  - Replaces S3 / Azure Blob ACLs with restrictive endpoint policies, instantly blocking data exfiltration channels during active breach scenarios.
- **Forensic Disk & Memory Snapshot (`PLAYBOOK-FORENSIC-SNAPSHOT`)**:
  - Maps to MITRE D3FEND **D3-FPA** (*Forensic Preservation Artifact*).
  - Triggers point-in-time point volume snapshots compliant with **ISO/IEC 27037** digital evidence standards.

---

## 🚀 Quick Start & CLI Usage

### Requirements
- Python 3.9+ (Standard Library only — zero pip dependencies required)

### Syntax & Available Options

```bash
python multicloud_soar_engine.py [OPTIONS]
```

| Parameter | Type | Description |
| :--- | :---: | :--- |
| `--alert, -a PATH` | `string` | Ingest GuardDuty, Sentinel, or GCP SCC finding JSON payload |
| `--playbook, -p ID` | `choice` | Playbook to trigger (`PLAYBOOK-ISO-COMPUTE`, `PLAYBOOK-REVOKE-IAM`, etc.) |
| `--target-id, -t ID` | `string` | Target resource ID (EC2 ID, IAM identity, or storage bucket) |
| `--live` | `flag` | Execute live remediation against cloud APIs (default is dry-run) |
| `--format FMT` | `choice` | Output format: `table` (default) or `json` |
| `--stats` | `flag` | Display live SOAR execution telemetry and Mean Time to Contain (MTTC) |

---

## 💻 Practical Usage Scenarios

### 1. Ingest AWS GuardDuty Finding & Trigger Auto-Containment
```bash
python multicloud_soar_engine.py --alert samples/guardduty_finding.json
```
**Sample Output:**
```text
======================================================================================
SOAR INCIDENT RESPONSE DISPATCH: SOAR-EXEC-184920
Playbook: Isolate Compromised Compute Workload [PLAYBOOK-ISO-COMPUTE]
Framework: MITRE D3FEND D3-NPA (Network Policed Access)
Target: [AWS] i-0987654321abcdef0
Execution Mode: [DRY_RUN] -> Status: COMPLETED
======================================================================================
Remediation Steps Executed:
  [1] Enforce Restrictive Security Group / NSG Quarantine Policy
      Revoked 0.0.0.0/0 ingress/egress on i-0987654321abcdef0; permitted incident response bastion only. -> (SIMULATED_SUCCESS)
  [2] Disable Public IP Association
      Detached Elastic/Public IP from network interface of i-0987654321abcdef0. -> (SIMULATED_SUCCESS)
======================================================================================
```

### 2. Revoke Compromised Azure AD Identity via Microsoft Sentinel Incident
```bash
python multicloud_soar_engine.py --alert samples/sentinel_incident.json
```

---

## 🧪 Automated Testing

Execute the test suite locally:
```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 📄 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
