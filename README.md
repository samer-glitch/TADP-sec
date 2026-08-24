# TADP-sec
## Trustworthy AI Data Preparation with Governance-to-Runtime Security for Federated Learning

TADP-Sec is a research framework that connects **evidence-based data/contributor
governance** with **runtime protection selection in federated learning (FL)**.

The framework extends Trustworthy AI Data Preparation (TADP) by introducing a
governance-to-security workflow in which:

1. contributor evidence is validated;
2. governance dimensions are scored under a fixed, versioned policy;
3. admissibility is determined using an overall HPS, a normalized critical HPS,
   and a non-compensatory critical-dimension floor;
4. only admitted contributors proceed to TADP-Sec;
5. confidentiality, integrity, availability (CIA), and Business Impact (BI)
   determine each admitted client's minimum protection requirement; and
6. one common session protection profile, equal to the strictest admitted
   requirement, is selected before federated round 1 and remains fixed for the
   lifetime of the session.

This repository contains the implementation, experimental outputs, and
supplementary material accompanying the TADP-Sec study.

---

## Framework Overview

TADP-Sec separates governance admission from runtime protection.

### Stage 1 — TADP Governance and Admission

The server derives authoritative governance scores from validated evidence.

The experimental policy uses six governance dimensions:

- Source Reliability
- Data Quality
- Documentation
- Timeliness
- Regulatory
- Context

The overall governance score is the **HPS**.

Four dimensions are treated as critical:

- Source Reliability
- Data Quality
- Regulatory
- Context

The admission policy therefore considers:

- overall HPS;
- normalized critical HPS (`HPS_C`); and
- the minimum score among the critical dimensions.

For the financial-fraud experimental profile:

- `T_R = 3.0`
- `T_A = 4.0`
- `T_C_direct = 4.0`
- `T_C_review = 3.5`
- `C_min = 3.0`

The resulting policy routes contributions to:

- direct acceptance;
- deterministic automated-review acceptance;
- remediation; or
- rejection.

The admission policy is fixed and versioned. It does not rank clients against
one another and does not impose a predetermined admission quota.

---

## Stage 2 — TADP-Sec Runtime Protection

Only admitted contributors proceed to the security-classification stage.

For each admitted contributor, validated CIA requirements are reduced to a
CIA high-water level and combined with Business Impact through the TADP-Sec
policy matrix.

The admitted cohort then operates under one session-wide protection profile:

\[
T_{\text{session}} = \max_{i \in A} T_i
\]

where `A` is the admitted cohort.

The selected session profile is fixed before federated round 1. It is not
downgraded or dynamically changed during the session.

A new contributor, materially changed dataset commitment, or materially
changed governance/security policy requires reassessment and formation of a
new session.

---

## Runtime Profiles

The implementation evaluates four runtime profiles.

### T1 — Governed Authenticated FL

Baseline governed federated learning with:

- signatures;
- freshness validation;
- anti-replay controls;
- Proof-of-Flow/Challenge (PoFC) participation control; and
- tamper-evident audit logging.

T1 does not provide encrypted aggregation.

### T2 — Modified Domingo-Ferrer + Matrix Key Switching

Research/reference protected-aggregation implementation based on:

- finite-field fixed-point transformation; and
- matrix key switching.

### T3 — xMK-CKKS

Multi-key CKKS reference implementation using collaborative decryption across
the participating clients.

### T4 — SAMK

Role-separated SAMK reference workflow based on:

- BFV;
- Paillier-protected helper information; and
- polynomial interpolation enabling authorized participating clients to
  independently recover the protected aggregate.

T2--T4 are research/reference implementations used for functional,
numerical-fidelity, runtime, and generated-payload evaluation. They are not
presented as production cryptographic deployments.

---

## Experimental Study

The reported experiment uses the canonical ULB/Kaggle credit-card-fraud
dataset.

### Dataset

- Total transactions: **284,807**
- Fraud transactions: **492**
- Normal transactions: **284,315**
- Number of federated clients: **20**

The dataset is partitioned across non-IID clients using class-conditional
Dirichlet allocation.

A common standard scaler is fitted only on the union of client-training data
and is subsequently applied to client, validation, and test records.

The canonical experiment uses:

- 5 random seeds;
- 20 federated rounds;
- 2 local epochs;
- batch size 32;
- learning rate 0.01.

The dataset itself is **not redistributed by this repository**. Users should
obtain `creditcard.csv` from the original ULB/Kaggle source and provide its
local path to the experiment.

---

## Governance Evidence in the Public-Dataset Experiment

The public credit-card-fraud dataset contains transaction features and labels
but does not contain organization-level governance evidence.

Therefore:

- **Data Quality** is measured from each client's actual local data partition;
- Source Reliability, Documentation, Timeliness, Regulatory, and Context are
  instantiated through fixed controlled experimental archetypes; and
- CIA/Business-Impact conditions are also represented through fixed controlled
  experimental archetypes.

These archetypes are used to exercise the governance and security workflow
under reproducible heterogeneous conditions.

They do **not** represent real organizations and should not be interpreted as
estimates of the prevalence of governance profiles in real deployments.

---

## Main Experimental Findings

Under the frozen governance policy:

- 20 candidate contributors were evaluated;
- 12 contributors were admitted;
- 8 contributors were not admitted.

The admitted cohort required a unified **T4** protection profile.

T1--T3 were therefore retained as controlled benchmark profiles over the same
admitted cohort for comparison of:

- predictive utility;
- numerical fidelity;
- runtime;
- generated protocol payload; and
- protocol-enforcement behavior.

Across the reported protected-aggregation experiments, all required numerical
fidelity gates passed.

The governed model remained non-inferior to the plain-FL reference under the
predefined Average Precision non-inferiority margin of `0.005`.

The protocol-enforcement experiments evaluated:

- invalid-signature rejection;
- stale/replayed submission rejection; and
- PoFC participation-limit enforcement.

These tests evaluate protocol enforcement only. They do not establish general
robustness against semantic data poisoning, backdoors, Byzantine clients, or
network-level denial-of-service attacks.

---

## Repository Structure

```text
TADP-Sec/
│
├── README.md
│
├── TADP-Sec_Canonical_Experiment and more results
│
├── TADP-Sec_Supplementary_Material.pdf
│
├── crypto_articfacts/
│
├── fig/
│
├── ledgers/
│
├── stats/
│
└── LICENSE
