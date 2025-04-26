# TerraGuard 🛡️

Lightweight, blazing-fast Rust CLI tool to detect Terraform security drifts and enforce network policies before and after deployments.

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)

## 📚 Table of Contents
- [Overview](#overview)
- [The Problem: Security Drift](#the-problem-security-drift)
- [Why TerraGuard?](#why-terraguard)
- [Architecture](#architecture)
- [Features](#features)
- [Quickstart](#quickstart)
- [Example Output](#example-output)
- [Policy File Example](#policy-file-example)
- [Real-world Examples](#real-world-examples)
- [Roadmap](#roadmap)
- [Tech Stack](#tech-stack)
- [Contributing](#contributing)
- [License](#license)

## 🚀 Overview

TerraGuard helps you:

- Parse Terraform plan.json outputs
- Validate security configurations before deployment
- Detect runtime drift post-deployment
- Enforce custom network security policies
- Integrate into CI/CD pipelines effortlessly

Focused on preventing common cloud misconfigurations that lead to real-world security breaches, such as:
- Open security groups (0.0.0.0/0)
- Public S3 buckets
- Unsafe IAM policies
- Firewall misconfigurations

## 🔍 The Problem: Security Drift

**A Simple Formula for Disaster:**
```
(Infra as Code) + (Manual Changes) + (No Monitoring) = Drift -> Breach
```

Security drift occurs when your deployed infrastructure no longer matches your Infrastructure as Code (IaC) like Terraform files. This happens constantly in real-world environments for various reasons:

- Manual changes to security groups, firewall rules through the cloud console
- Automated tools/scripts mutating infrastructure outside Terraform
- Different teams (Ops, DevSecOps, Devs) editing settings directly
- Scheduled tasks dynamically adjusting network configurations

Surveys and security reports show drift is among the top 3 reasons for:
- Unexpected breaches
- Open ports to the internet
- Firewall misconfigurations

Even Fortune 500 companies suffer from this, making it one of the biggest sources of cloud vulnerabilities today.

## 📌 Why TerraGuard?

Terraform itself doesn't handle drift well at runtime:

| Feature | Terraform | TerraGuard |
|---------|-----------|------------|
| Validate network security policies before deployment | ❌ | ✅ |
| Parse plan files and enforce custom security rules | ❌ | ✅ |
| Continuous runtime monitoring for drifted security groups/firewalls | ❌ | ✅ (optional) |
| Lightweight integration in Rust apps | ❌ | ✅ |
| Alert on policy violation even after deployment | ❌ | ✅ |

TerraGuard exists to plug the security gap without forcing Rust developers to rebuild their entire workflow.

### 🧱 MVP Components:

- **Plan Parser**: Parses Terraform plan JSON
- **Policy Engine**: Applies user-defined security policies
- **Optional Runtime Monitor**: Fetches live infrastructure configuration via APIs (AWS, GCP, Azure)
- **Report Generator**: Outputs findings as terminal logs + machine-readable JSON

## ✨ Features

- ✅ Lightweight Rust CLI
- ✅ Parse Terraform plan files
- ✅ Custom security policies (YAML/JSON)
- ✅ Fast plan validation
- ✅ Optional runtime drift monitoring
- ✅ Clear CLI output + JSON reports
- ✅ Easy CI/CD integration
- ✅ Extensible for other resources (e.g., EBS encryption, IAM roles)

## ⚡ Quickstart

### Install TerraGuard

```bash
cargo install terraguard
```
(Or clone + build locally)

### Run Terraform Plan

```bash
terraform plan -out=plan.tfplan
terraform show -json plan.tfplan > plan.json
```

### Validate with TerraGuard

```bash
terraguard validate --plan plan.json --policy ./policies/basic.yaml
```

## 🖥️ Example Output

```bash
✅ [PASS] No public ingress detected
❌ [FAIL] S3 bucket "customer-data" is public
❌ [FAIL] Security Group "db-sg" allows port 27017 to 0.0.0.0/0
```
(also generates a JSON report: terraguard-report.json)

## 📄 Policy File Example

Example YAML policy (basic.yaml):

```yaml
rules:
  - name: "NoPublicIngress"
    type: "security_group"
    match:
      cidr: "0.0.0.0/0"
      ports: ["22", "27017", "3306", "5432"]
    action: "deny"

  - name: "NoPublicS3Buckets"
    type: "s3_bucket"
    match:
      public_access: true
    action: "deny"
```

Users can define custom security rules in an easy-to-edit format.

## 🛣️ Roadmap

| Feature | Status |
|---------|--------|
| Terraform plan parsing | ✅ Done |
| Policy engine for security groups and S3 | ✅ Done |
| JSON/terminal report output | ✅ Done |
| Optional runtime drift detection (AWS) | 🔜 Coming soon |
| GitHub Action/CI integration examples | 🔜 Coming soon |
| Extend to IAM Policies, Load Balancers | 🔜 Future |
| Web dashboard for reporting | 🎯 Stretch goal |

## 🧰 Tech Stack

- **Rust** - safe, fast systems language
- **Serde** - serialization/deserialization
- **Clap** - building CLI
- **Tokio** - async runtime (for future AWS/GCP API calls)
- **AWS SDK for Rust** (optional runtime monitoring)

## 👥 Contributing

We love contributions! 💖

1. Fork this repository
2. Create a feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request 🚀

Please follow the Rust style guide and write tests where applicable.

## 📜 License

This project is licensed under the MIT License. See the LICENSE file for details.

---

TerraGuard is built with ❤️ by security-minded engineer who believe infrastructure should be safe by default.
Secure your cloud. Protect your users. Sleep better. 🛡️🌙
