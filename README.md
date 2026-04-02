# Open Source Supply Chain Security Landscape

> **Unified Model**: Merges [SLSA](https://slsa.dev), [S2C2F](https://github.com/ossf/s2c2f), [NIST SSDF](https://csrc.nist.gov/Projects/ssdf), and [CNCF SSC Best Practices](https://github.com/cncf/tag-security) into **8 lifecycle phases** covering both producer and consumer perspectives.

> **🤖 NEW**: [AI / ML Supply Chain Security Landscape](#ai--ml-supply-chain-security-landscape) — A dedicated 8-phase model covering the full AI lifecycle from training data to production monitoring.

## Table of Contents

- [Unified Supply Chain Model](#unified-supply-chain-model)
- [Phase 1: Source Code & Version Control](#phase-1-source-code--version-control)
- [Phase 2: Dependency Management & Ingestion](#phase-2-dependency-management--ingestion)
- [Phase 3: Build & CI/CD Integrity](#phase-3-build--cicd-integrity)
- [Phase 4: Artifact Signing & Provenance](#phase-4-artifact-signing--provenance)
- [Phase 5: Package Distribution & Registry](#phase-5-package-distribution--registry)
- [Phase 6: Vulnerability Scanning & Analysis](#phase-6-vulnerability-scanning--analysis)
- [Phase 7: SBOM & Inventory Management](#phase-7-sbom--inventory-management)
- [Phase 8: Monitoring, Update & Incident Response](#phase-8-monitoring-update--incident-response)
- [Cross-Cutting Gap Analysis](#cross-cutting-gap-analysis)
- [Frameworks & Standards Reference](#frameworks--standards-reference)
- [Foundation Index](#foundation-index)
- [AI / ML Supply Chain Security Landscape](#ai--ml-supply-chain-security-landscape)

---

## Unified Supply Chain Model

| # | Phase | SLSA Mapping | S2C2F Mapping | SSDF Mapping |
|---|-------|-------------|---------------|-------------|
| 1 | **Source Code & Version Control** | Threats A, B | — | PW (Produce Well-Secured Software) |
| 2 | **Dependency Management & Ingestion** | Threats D, H | Practice 1 (Ingest), Practice 6 (Enforce) | PW.4 (Reuse existing software) |
| 3 | **Build & CI/CD Integrity** | Threats C, E | Practice 7 (Rebuild) | PW.6 (Configure compilation) |
| 4 | **Artifact Signing & Provenance** | Provenance, Build L1-L3 | Practice 5 (Audit) | PS.1/PS.2 (Protect Software) |
| 5 | **Package Distribution & Registry** | Threats F, G | Practice 1 (Ingest — mirror side) | PS.1 (Protect Software) |
| 6 | **Vulnerability Scanning & Analysis** | — | Practice 2 (Scan) | RV.1 (Identify Vulnerabilities) |
| 7 | **SBOM & Inventory Management** | — | Practice 3 (Inventory) | PS.3 (Provide SBOM) |
| 8 | **Monitoring, Update & Incident Response** | Availability | Practice 4 (Update), Practice 8 (Fix+Upstream) | RV.2/RV.3 (Respond) |

```
  ┌──────────┐   ┌──────────────┐   ┌─────────┐   ┌──────────┐   ┌──────────────┐   ┌──────────┐   ┌──────┐   ┌──────────────┐
  │ 1.Source  │──▶│2.Dependencies│──▶│ 3.Build │──▶│4.Signing │──▶│5.Distribution│──▶│6.Scanning│──▶│7.SBOM│──▶│ 8.Monitor &  │
  │   Code   │   │ & Ingestion  │   │ & CI/CD │   │&Provenance│  │  & Registry  │   │& Analysis│   │      │   │   Respond    │
  └──────────┘   └──────────────┘   └─────────┘   └──────────┘   └──────────────┘   └──────────┘   └──────┘   └──────────────┘
```

---

## Phase 1: Source Code & Version Control

**Objective**: Secure source code repositories, enforce access controls, branch protections, commit signing, and code review policies.

### Threats
- Unauthorized commit injection
- Compromised developer credentials
- Malicious code review bypass
- Repository takeover / hijack
- Force-push rewriting history
- Insider threat — malicious maintainer

### Controls & Tools

| Control | Tool | Foundation | Maturity | Description |
|---------|------|------------|----------|-------------|
| Branch protection, signed commits, delegation trust | [gittuf](https://github.com/gittuf/gittuf) | OpenSSF | Incubating | TUF-based delegation and trust policies for Git repos |
| Branch protection, code review, access audit | [Scorecard](https://securityscorecards.dev) | OpenSSF | Graduated | Automated security health metrics for OSS projects |
| Access audit, code review | [CII Best Practices Badge](https://www.bestpractices.dev) | OpenSSF | Graduated | Self-certification for FLOSS security best practices |
| Branch protection, signed commits, review, audit | [OSPS Baseline](https://baseline.openssf.org) | OpenSSF | Active | Minimum security requirements at maturity levels |
| Branch protection, review, audit | [Allstar](https://github.com/ossf/allstar) | OpenSSF | Active | GitHub App enforcing repository security policies |
| Branch protection, review, audit | [Minder](https://github.com/mindersec/minder) | OpenSSF | Sandbox | Policy-as-code for repositories and artifacts |
| Tool output interchange | [SARIF](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif) | OASIS | Standard | Static analysis results interchange format |
| Secret scanning | [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Community | Production | Secret detection across Git history and filesystems |

### Gaps

| Gap | Severity | Detail |
|-----|----------|--------|
| **Insider threat detection** | 🔴 RED | No OSS tool detects malicious maintainer behavior (e.g., xz-utils social engineering takeover) |
| **Small project adoption barrier** | 🟡 YELLOW | Tools assume GitHub/GitLab + CI sophistication. Self-hosted forges lack equivalents |
| **Cross-forge policy portability** | 🟡 YELLOW | Allstar/Minder are GitHub-centric. No universal policy standard for GitLab, Gitea, Forgejo |

---

## Phase 2: Dependency Management & Ingestion

**Objective**: Evaluate, select, and securely ingest open source dependencies. Manage transitive risk, license compliance, and trusted sources.

### Threats
- Typosquatting / dependency confusion
- Compromised upstream package
- Malicious transitive dependency
- Abandoned / unmaintained dependency
- License compliance violation
- Protestware / self-sabotage

### Controls & Tools

| Control | Tool | Foundation | Maturity | Description |
|---------|------|------------|----------|-------------|
| Health evaluation, criticality monitoring | [Criticality Score](https://github.com/ossf/criticality_score) | OpenSSF | Active | Quantifies open source project importance |
| Health evaluation, allow/deny lists | [Package Analysis](https://github.com/ossf/package-analysis) | OpenSSF | Active | Sandboxed behavioral analysis of packages |
| Health evaluation | [Package Feeds](https://github.com/ossf/package-feeds) | OpenSSF | Active | Monitors registries for new packages |
| Version pinning, mirrors, policies | [S2C2F Spec](https://github.com/ossf/s2c2f) | OpenSSF | Specification | Prescriptive framework for secure OSS consumption |
| License compliance | [OpenChain ISO 5230](https://www.openchainproject.org) | LF | Standard | International standard for OSS license compliance |
| Health evaluation | [Dependency-Check](https://owasp.org/www-project-dependency-check/) | OWASP | Flagship | Detects known vulnerabilities in dependencies |
| Pinning, evaluation, policies | [SCVS](https://scvs.owasp.org) | OWASP | Incubating | Software component verification standard |
| Evaluation, license compliance | [dep-scan](https://github.com/owasp-dep-scan/dep-scan) | OWASP | Incubating | Security audit with SBOM + reachability |
| License compliance | [Dash License Tool](https://github.com/eclipse/dash-licenses) | Eclipse | Production | License verification for Eclipse projects |
| Version pinning | [Renovate](https://github.com/renovatebot/renovate) | Community | Production | Automated dependency updates for 70+ ecosystems |
| Evaluation, allow/deny lists | [Socket.dev](https://socket.dev) | Community | Production | Supply chain attack detection via behavior analysis |

### Gaps

| Gap | Severity | Detail |
|-----|----------|--------|
| **Protestware / self-sabotage detection** | 🔴 RED | No automated tool reliably detects maintainer-initiated sabotage |
| **Transitive dependency risk scoring** | 🟡 YELLOW | No standard for cascading risk scores through dependency trees |
| **Cross-ecosystem policy enforcement** | 🟡 YELLOW | No unified ingestion policy engine spans all package ecosystems |

---

## Phase 3: Build & CI/CD Integrity

**Objective**: Ensure builds are tamper-resistant, reproducible, and CI/CD pipelines are hardened against injection and compromise.

### Threats
- Compromised build system / CI runner
- Build script injection
- Non-reproducible builds hiding tampering
- Dependency substitution at build time
- CI/CD secret exfiltration
- Pipeline poisoning (PPE attacks)

### Controls & Tools

| Control | Tool | Foundation | Maturity | Description |
|---------|------|------------|----------|-------------|
| Hermetic builds, provenance, reproducibility | [SLSA Framework](https://slsa.dev) | OpenSSF | Specification | Build L1-L3 levels for build integrity |
| Provenance, hermetic builds | [SLSA GitHub Generator](https://github.com/slsa-framework/slsa-github-generator) | OpenSSF | Active | GitHub Actions SLSA L3 provenance generators |
| Hermetic builds, provenance, CI hardening | [FRSCA](https://github.com/buildsec/frsca) | OpenSSF | Experimental | Reference architecture for secure build pipelines |
| Provenance, CI hardening | [in-toto](https://in-toto.io) | CNCF | Graduated | Supply chain integrity verification framework |
| Provenance, hermetic builds | [Tekton Chains](https://tekton.dev/docs/chains/) | CNCF | Active | K8s-native supply chain signing & provenance |
| Provenance, CI hardening | [Witness](https://github.com/in-toto/witness) | Community | Active | Pluggable supply chain attestation framework |
| Reproducible builds | [Reproducible Builds](https://reproducible-builds.org) | Community | Active | Cross-ecosystem deterministic build initiative |
| Hermetic builds, ephemeral environments | [Cloud Native Buildpacks](https://buildpacks.io) | CNCF | Incubating | Standardized container image build process |

### Gaps

| Gap | Severity | Detail |
|-----|----------|--------|
| **CI/CD pipeline poisoning detection** | 🔴 RED | No comprehensive OSS tool detects PPE attacks in CI configurations |
| **Non-GitHub build provenance** | 🟡 YELLOW | SLSA generators mature on GitHub Actions; limited for GitLab CI, Jenkins, CircleCI |
| **Reproducible builds at scale** | 🟡 YELLOW | Despite years of work, most ecosystems cannot achieve reproducible builds by default |

---

## Phase 4: Artifact Signing & Provenance

**Objective**: Cryptographically sign artifacts and generate verifiable provenance attestations to prove authenticity and integrity.

### Threats
- Artifact tampering post-build
- Key compromise / stolen signing keys
- Lack of provenance — cannot verify origin
- Signature stripping attacks
- Long-lived key management burden
- Fake provenance / forged attestations

### Controls & Tools

| Control | Tool | Foundation | Maturity | Description |
|---------|------|------------|----------|-------------|
| Keyless signing, transparency log, timestamps | [Sigstore](https://sigstore.dev) | OpenSSF | Graduated | Keyless signing infrastructure (Cosign + Fulcio + Rekor) |
| Keyless signing, verification | [Cosign](https://github.com/sigstore/cosign) | OpenSSF | Graduated | Container signing and verification |
| Keyless signing, key management | [Fulcio](https://github.com/sigstore/fulcio) | OpenSSF | Graduated | Free root CA for code signing certificates |
| Transparency log, timestamps | [Rekor](https://github.com/sigstore/rekor) | OpenSSF | Graduated | Tamper-resistant transparency log |
| Key management, verification | [TUF](https://theupdateframework.io) | CNCF | Graduated | Secure software update framework |
| Key management, verification | [RSTUF](https://github.com/repository-service-tuf/repository-service-tuf) | OpenSSF | Incubating | Production TUF repository service |
| Keyless signing, verification | [Notary/Notation](https://notaryproject.dev) | CNCF | Incubating | Container image signing with trust policies |
| Keyless signing, ML provenance | [Model Signing](https://github.com/sigstore/model-transparency) | OpenSSF | Experimental | Sigstore-based ML model signing |
| Provisioning attestation | [DPS (OASIS)](https://www.oasis-open.org) | OASIS | Standard | Secure device/firmware provisioning standards |

### Gaps

| Gap | Severity | Detail |
|-----|----------|--------|
| **AI/ML model provenance** | 🔴 RED | Model Signing is experimental; no production standard for ML model chain-of-custody |
| **Consumer-side verification tooling** | 🔴 RED | No turnkey solution for automated verification of all incoming signatures and provenance |
| **Cross-ecosystem signing adoption** | 🟡 YELLOW | Container signing mature; npm, Maven, Cargo, RubyGems signing maturity varies widely |

---

## Phase 5: Package Distribution & Registry

**Objective**: Securely distribute and host artifacts, ensuring integrity and availability, and protecting against registry-level attacks.

### Threats
- Registry compromise / account takeover
- Package substitution in transit
- Registry availability attacks (DoS)
- Namespace squatting / hijacking
- Stale / abandoned package takeover
- Mirror desynchronization / poisoning

### Controls & Tools

| Control | Tool | Foundation | Maturity | Description |
|---------|------|------------|----------|-------------|
| Access controls, integrity, mirrors | [Harbor](https://goharbor.io) | CNCF | Graduated | Enterprise container registry with security features |
| Integrity, content-addressable storage | [TUF (for registries)](https://theupdateframework.io) | CNCF | Graduated | Secure update delivery for package registries |
| Air-gapped distribution | [Zarf](https://zarf.dev) | OpenSSF | Sandbox | Declarative air-gap K8s package manager |
| End-of-life signaling | [OpenEoX](https://github.com/oasis-tcs/openeox) | OASIS | Draft | Standard for EOL/EOS communication |
| Content-addressable storage, integrity | [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec) | Community | Standard | Container artifact distribution standard |
| Accelerated distribution | [Dragonfly](https://d7y.io) | CNCF | Incubating | P2P image distribution with integrity |

### Gaps

| Gap | Severity | Detail |
|-----|----------|--------|
| **Universal registry tamper protection** | 🟡 YELLOW | No universal mechanism for tamper-proof registries across all ecosystems |
| **Namespace squatting prevention** | 🟡 YELLOW | No cross-ecosystem standard for preventing namespace/name squatting |
| **Non-container artifact registries** | 🟡 YELLOW | Most OSS registry tooling targets containers; other ecosystems have fewer options |

---

## Phase 6: Vulnerability Scanning & Analysis

**Objective**: Identify vulnerabilities, assess exploitability, prioritize remediation through automated scanning, advisory frameworks, and fuzzing.

### Threats
- Known vulnerabilities in dependencies
- Zero-day vulnerabilities
- False negatives in scanners
- Alert fatigue from false positives
- Delayed vulnerability disclosure
- Incomplete vulnerability databases

### Controls & Tools

| Control | Tool | Foundation | Maturity | Description |
|---------|------|------------|----------|-------------|
| Vulnerability DB, continuous scanning | [OSV / OSV-Scanner](https://osv.dev) | Community | Production | Distributed vulnerability DB + scanner |
| VEX communication | [OpenVEX](https://openvex.dev) | OpenSSF | Active | Vulnerability exploitability exchange implementation |
| Advisories, VEX, disclosure | [CSAF 2.0](https://oasis-open.github.io/csaf-documentation/) | OASIS | Standard | Machine-readable security advisory framework |
| Fuzzing coverage | [Fuzz Introspector](https://github.com/ossf/fuzz-introspector) | OpenSSF | Active | Fuzzer effectiveness analysis |
| Fuzzing | [OSS-Fuzz](https://github.com/google/oss-fuzz) | Community | Production | Continuous fuzzing for open source projects |
| Continuous scanning | [Trivy](https://trivy.dev) | Community | Production | Comprehensive vulnerability scanner |
| Continuous scanning | [Grype](https://github.com/anchore/grype) | Community | Production | Container / filesystem vulnerability scanner |
| Component tracking, scanning | [SW360](https://www.eclipse.org/sw360/) | Eclipse | Production | Software component catalogue and license management |
| AI/ML security | [CoSAI](https://www.coalitionforsecureai.org) | OASIS | Forming | AI security assessment framework |
| Assessment normalization | [OHDF](https://saf.mitre.org) | OASIS | Active | Standardized security assessment results format |

### Gaps

| Gap | Severity | Detail |
|-----|----------|--------|
| **AI/ML model vulnerability scanning** | 🔴 RED | No OSS scanner assesses ML models for adversarial vulnerabilities or backdoors |
| **Reachability / exploitability analysis** | 🟡 YELLOW | Most scanners report all CVEs without assessing whether code is actually reachable |
| **VEX adoption** | 🟡 YELLOW | Standards exist but most vendors don't publish VEX documents |

---

## Phase 7: SBOM & Inventory Management

**Objective**: Generate, distribute, consume, and manage Software Bills of Materials for transparency, compliance, and vulnerability management.

### Threats
- Incomplete or inaccurate SBOM
- Format fragmentation (SPDX vs CycloneDX)
- SBOM not kept in sync with releases
- Inability to consume SBOMs at scale
- Missing transitive dependency information
- No SBOM fitness/quality scoring

### Controls & Tools

| Control | Tool | Foundation | Maturity | Description |
|---------|------|------------|----------|-------------|
| Format standard, generation | [SPDX (ISO 5962)](https://spdx.dev) | LF | Standard | International SBOM standard |
| Format standard, generation, vuln linking | [CycloneDX](https://cyclonedx.org) | OWASP | Standard | Lightweight SBOM + VEX + ML-BOM standard |
| Format translation, merging | [bomctl](https://github.com/bomctl/bomctl) | OpenSSF | Sandbox | Format-agnostic SBOM tooling |
| Format translation | [protobom](https://github.com/protobom/protobom) | OpenSSF | Sandbox | Lossless SPDX ↔ CycloneDX translation |
| SBOM attestation | [SBOMit](https://github.com/sbomit) | OpenSSF | Experimental | SBOM + in-toto provenance attestation |
| SBOM querying, vuln linking | [GUAC](https://guac.sh) | OpenSSF | Incubating | Supply chain knowledge graph |
| SBOM consumption, portfolio tracking | [Dependency-Track](https://dependencytrack.org) | OWASP | Flagship | Continuous SBOM analysis platform |
| SBOM generation | [Syft](https://github.com/anchore/syft) | Community | Production | SBOM generator for containers and filesystems |
| SBOM generation | [Tern](https://github.com/tern-tools/tern) | Community | Active | Container image SBOM inspector |
| Supply chain modeling | [OSIM](https://www.oasis-open.org) | OASIS | Forming | Unified supply chain information modeling |
| Vulnerability severity | [VSMI](https://www.oasis-open.org) | OASIS | Draft | Vulnerability severity metadata standardization |

### Gaps

| Gap | Severity | Detail |
|-----|----------|--------|
| **AI/ML BOM maturity** | 🔴 RED | CycloneDX ML-BOM exists in draft but tooling for generating ML-BOMs is virtually non-existent |
| **SBOM quality scoring** | 🟡 YELLOW | No widely adopted standard for SBOM completeness/quality assessment |
| **SPDX vs CycloneDX fragmentation** | 🟡 YELLOW | Two competing standards create tooling fragmentation; translation tools are immature |
| **SBOM consumption at scale** | 🟡 YELLOW | Generating is increasingly automated; consuming thousands of SBOMs is still challenging |

---

## Phase 8: Monitoring, Update & Incident Response

**Objective**: Continuously monitor deployed software, automate patching, respond to supply chain incidents, and contribute fixes upstream.

### Threats
- Delayed patching of known vulnerabilities
- Regression from updates
- Lack of coordinated incident response
- No visibility into deployed component versions
- Supply chain attack propagation
- Unclear responsibility for OSS fixes

### Controls & Tools

| Control | Tool | Foundation | Maturity | Description |
|---------|------|------------|----------|-------------|
| Upstream fix contribution | [Alpha-Omega](https://openssf.org/community/alpha-omega/) | OpenSSF | Active | Improving security of critical OSS projects |
| Disclosure processes, incident playbooks | [OpenSSF Guides](https://openssf.org/resources/guides/) | OpenSSF | Active | Practical security guides for OSS |
| Incident response playbooks | [CACAO](https://www.oasis-open.org/committees/cacao/) | OASIS | Standard | Machine-readable security playbook automation |
| Incident response, runtime monitoring | [OpenC2](https://openc2.org) | OASIS | Standard | Automated cyber defense command-and-control |
| Disclosure, threat intelligence | [STIX/TAXII](https://oasis-open.github.io/cti-documentation/) | OASIS | Standard | Cyber threat intelligence sharing standards |
| Runtime monitoring | [OCA](https://opencybersecurityalliance.org) | OASIS | Active | Interoperable security tooling initiative |
| Deployment tracking, transparency | [SCITT](https://scitt.io) | IETF | Draft | Supply chain transparency registry architecture |
| Automated updates | [Renovate](https://github.com/renovatebot/renovate) | Community | Production | Automated dependency updates (70+ ecosystems) |
| Automated updates | [Dependabot](https://github.com/dependabot) | Community | Production | GitHub-native dependency update service |
| Runtime detection | [Falco](https://falco.org) | CNCF | Graduated | Cloud-native runtime security with eBPF |
| Runtime policy, deployment tracking | [Kyverno](https://kyverno.io) | CNCF | Incubating | K8s-native policy engine with supply chain support |

### Gaps

| Gap | Severity | Detail |
|-----|----------|--------|
| **Multi-org coordinated response** | 🔴 RED | No open standard for coordinating supply chain incident response across multiple organizations |
| **Small project incident capacity** | 🔴 RED | Most small OSS projects have zero incident response capacity |
| **Deployed component inventory** | 🟡 YELLOW | Runtime SBOM tracking (deployed vs. built) is largely unsolved; SCITT still in draft |
| **End-to-end policy enforcement** | 🟡 YELLOW | No unified policy-as-code engine spans all 8 phases |

---

## Cross-Cutting Gap Analysis

These gaps span multiple phases and represent the most significant systemic risks in the OSS supply chain:

| Gap | Severity | Affected Phases | Description |
|-----|----------|----------------|-------------|
| **AI/ML Supply Chain Security** | 🔴 RED | Signing, Scanning, SBOM | Almost no production tooling for model provenance, training data integrity, poisoning detection, or ML-BOM |
| **Consumer-Side Verification at Scale** | 🔴 RED | Signing, Distribution, SBOM | Most tools focus on producers; automated consumer verification at enterprise scale is underdeveloped |
| **Small Project Adoption** | 🟡 YELLOW | Source, Build, Signing, Monitor | Tools assume CI/CD sophistication and dedicated resources that many critical small projects lack |
| **Cross-Ecosystem Consistency** | 🟡 YELLOW | Dependencies, Signing, Distribution | Each ecosystem (npm, PyPI, Maven, Go, Cargo) has different security capabilities with no unified standard |
| **End-to-End Policy Engine** | 🟡 YELLOW | All phases | No single policy-as-code system covers the entire supply chain lifecycle |
| **Standard Interoperability** | 🟡 YELLOW | Scanning, SBOM | SPDX vs CycloneDX, CSAF vs OSV, multiple VEX formats create ongoing integration overhead |

---

## Frameworks & Standards Reference

| Framework | Foundation | Scope | URL |
|-----------|----------- |-------|-----|
| SLSA (Supply-chain Levels for Software Artifacts) | OpenSSF | Build integrity, provenance | [slsa.dev](https://slsa.dev) |
| S2C2F (Secure Supply Chain Consumption Framework) | OpenSSF | 8-practice consumer framework | [github.com/ossf/s2c2f](https://github.com/ossf/s2c2f) |
| SSDF (NIST SP 800-218) | NIST | Secure development practices | [csrc.nist.gov](https://csrc.nist.gov/Projects/ssdf) |
| CNCF SSC Best Practices | CNCF | Cloud-native supply chain | [CNCF TAG-Security](https://github.com/cncf/tag-security) |
| OWASP SCVS | OWASP | Software component verification | [scvs.owasp.org](https://scvs.owasp.org) |
| OpenChain (ISO/IEC 5230) | LF | License compliance | [openchainproject.org](https://www.openchainproject.org) |

---

## Foundation Index

| Foundation | Abbreviation | Tools/Standards in This Map | Focus |
|------------|-------------|----------------------------|-------|
| [OpenSSF](https://openssf.org) | OpenSSF | ~25 tools | Security tooling, frameworks, best practices for OSS |
| [CNCF](https://cncf.io) | CNCF | ~10 projects | Cloud-native runtime, signing, build, policy |
| [OASIS Open](https://www.oasis-open.org) | OASIS | ~10 standards | Advisory formats, threat intel, playbooks, AI security |
| [Eclipse Foundation](https://www.eclipse.org) | Eclipse | ~3 projects | License compliance, component management |
| [OWASP](https://owasp.org) | OWASP | ~5 projects | Dependency checking, SBOM, component verification |
| [Linux Foundation](https://www.linuxfoundation.org) | LF | ~3 standards | SPDX, OpenChain, governance |
| [IETF](https://www.ietf.org) | IETF | ~1 draft | SCITT transparency architecture |
| Community / Independent | Community | ~10 projects | Trivy, Grype, Renovate, Reproducible Builds, etc. |

---

## AI / ML Supply Chain Security Landscape

> **Dedicated AI Model**: Maps [NIST AI RMF](https://airc.nist.gov/AI_RMF_Playbook), [OWASP ML/LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/), [MITRE ATLAS](https://atlas.mitre.org), and emerging AI governance standards into **8 AI lifecycle phases**.

Open [`ai-supply-chain-security.html`](ai-supply-chain-security.html) for the full interactive visualization, or see the data at [`data/ai-supply-chain-data.json`](data/ai-supply-chain-data.json).

### AI Supply Chain Phases

| # | Phase | Key Focus | Tools | Critical Gaps |
|---|-------|-----------|-------|------|
| 1 | **Training Data Sourcing & Curation** | Data poisoning, PII, bias, provenance | Croissant, DVC, Presidio, Cleanlab, AIF360 | Poisoning detection, copyright verification |
| 2 | **Model Development & Training** | Reproducible pipelines, training integrity | MLflow, Kubeflow, DVC, Metaflow | Training tamper detection, fine-tuning CoC |
| 3 | **Model Packaging & Signing** | Safe serialization, model signing | Sigstore Model Signing, Safetensors, ModelScan, fickling | Signing adoption near zero, provenance gap |
| 4 | **Model Registry & Distribution** | Hub security, integrity verification | Hugging Face Hub, MLflow Registry, ORAS, Harbor | No hub security standard, typosquatting |
| 5 | **Model Evaluation & Red Teaming** | Adversarial testing, prompt injection, bias | PyRIT, Garak, ART, HELM, Inspect AI, DeepEval | Multimodal eval gap, benchmark fragmentation |
| 6 | **AI BOM & Transparency** | Model cards, ML-BOM, datasheets | CycloneDX ML-BOM, SPDX AI, Model Cards, CodeCarbon | ML-BOM tooling, training data transparency |
| 7 | **Deployment & Runtime Security** | Guardrails, prompt injection defense | NeMo Guardrails, LLM Guard, Guardrails AI, Vigil | Prompt injection unsolved, agent security |
| 8 | **Monitoring, Governance & Response** | Drift, compliance, incident response | Evidently AI, NIST AI RMF, MITRE ATLAS, CoSAI | AI incident response, cross-org coordination |

```
  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
  │ 1.Data   │──▶│2.Training│──▶│3.Package │──▶│4.Registry│──▶│5.Evaluate│──▶│ 6.AI BOM │──▶│7.Deploy  │──▶│8.Govern  │
  │ Sourcing │   │& Dev     │   │& Signing │   │& Distrib │   │& Red Team│   │&Transpare│   │& Runtime │   │& Monitor │
  └──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘
```

### AI Cross-Cutting Gaps

| Gap | Severity | Affected Phases |
|-----|----------|-----------------|
| **End-to-End AI Supply Chain Standard** | 🔴 RED | All 8 phases — no equivalent of SLSA for AI |
| **Foundation Model Transparency** | 🔴 RED | Data, Training, AI BOM — training data/process not disclosed |
| **Fine-Tuning Chain of Custody** | 🔴 RED | Training, Packaging, Registry — no provenance through fine-tuning |
| **Agentic AI Security** | 🔴 RED | Deployment, Governance — tool-using agents create new attack surfaces |
| **AI Security Tooling Fragmentation** | 🟡 YELLOW | Evaluation, Deployment, Governance — no unified pipeline |
| **Regulatory Alignment** | 🟡 YELLOW | AI BOM, Governance — EU AI Act, NIST AI RMF, ISO 42001 diverge |

### AI Frameworks & Standards

| Framework | Organization | Scope |
|-----------|-------------|-------|
| [NIST AI RMF 1.0](https://airc.nist.gov/AI_RMF_Playbook) | NIST | GOVERN, MAP, MEASURE, MANAGE functions for AI risk |
| [MITRE ATLAS](https://atlas.mitre.org) | MITRE | Adversarial ML tactics & techniques knowledge base |
| [OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/) | OWASP | ML security risks (poisoning, inversion, theft) |
| [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | OWASP | LLM-specific risks (prompt injection, data leakage) |
| [EU AI Act](https://artificialintelligenceact.eu) | EU | Risk-based classification, conformity assessment |
| [ISO/IEC 42001](https://www.iso.org/standard/81230.html) | ISO | AI management system standard |
| [CoSAI](https://www.coalitionforsecureai.org) | OASIS | Industry AI security specifications |

---

## Interactive Visualizations

### Open Source Supply Chain
Open [`supply-chain-security.html`](supply-chain-security.html) in a browser for an interactive visualization including:
- **Pipeline flow** — clickable 8-phase horizontal pipeline
- **Heatmap matrix** — Phase × Foundation coverage density with gap severity coloring
- **Detail panels** — threats, controls, tools, and gaps per phase
- **Search & filter** — by foundation, tool name, or gap severity

### AI / ML Supply Chain
Open [`ai-supply-chain-security.html`](ai-supply-chain-security.html) for the AI-specific interactive visualization including:
- **Pipeline flow** — 8-phase AI lifecycle from data to governance
- **Heatmap matrix** — Phase × Organization coverage (NIST, OWASP, MITRE, OpenSSF, MLCommons, CoSAI, LF AI, Community)
- **Detail panels** — AI-specific threats, controls, tools, and gaps per phase
- **Gap analysis** — 6 cross-cutting gaps + per-phase breakdown
- **Framework view** — NIST AI RMF, MITRE ATLAS, OWASP ML/LLM Top 10, EU AI Act, ISO 42001, CoSAI

---

*Generated: 2026-04-01 | Data: 70+ OSS tools across 8 foundations + 55+ AI/ML tools across 8 organizations | Models: SLSA + S2C2F + SSDF unified lifecycle; NIST AI RMF + MITRE ATLAS + OWASP ML/LLM unified AI lifecycle*
