TADP-Sec
Trustworthy AI Data Preparation with Governance-to-Runtime Security for Federated Learning

TADP-Sec is a research framework that connects evidence-based data/contributor
governance with runtime protection selection in federated learning (FL).

The framework extends Trustworthy AI Data Preparation (TADP) by introducing a
governance-to-security workflow in which:

contributor evidence is validated;
governance dimensions are scored under a fixed, versioned policy;
admissibility is determined using an overall HPS, a normalized critical HPS,
and a non-compensatory critical-dimension floor;
only admitted contributors proceed to TADP-Sec;
confidentiality, integrity, availability (CIA), and Business Impact (BI)
determine each admitted client's minimum protection requirement; and
one common session protection profile, equal to the highest policy-ranked
admitted-client requirement, is selected before federated round 1 and remains
fixed for the lifetime of the session.

This repository contains the implementation, experimental outputs, and
supplementary material accompanying the TADP-Sec study.

Framework Overview

TADP-Sec separates governance admission from runtime protection.

Stage 1 — TADP Governance and Admission

The server derives authoritative governance scores from validated evidence.

The experimental policy uses six governance dimensions:

Source Reliability
Data Quality
Documentation
Timeliness
Regulatory
Context

The overall governance score is the HPS.

Four dimensions are treated as critical:

Source Reliability
Data Quality
Regulatory
Context

The admission policy therefore considers:

overall HPS;
normalized critical HPS (HPS_C); and
the minimum score among the critical dimensions.

For the frozen financial_fraud_experimental_profile_v2 policy:

T_R = 3.0
T_A = 4.0
T_C_review = 3.5
C_min = 3.0

There is no separate T_C_direct threshold in the final v14.0 policy.
Direct acceptance requires HPS >= T_A together with satisfaction of the
critical-dimension floor. Contributors in the review band
T_R <= HPS < T_A are accepted only when the critical-dimension floor is
satisfied and HPS_C >= T_C_review.

The resulting policy routes contributions to:

direct acceptance;
deterministic automated-review acceptance;
remediation; or
rejection.

The admission policy is fixed and versioned. It does not rank clients against
one another and does not impose a predetermined admission quota.

Stage 2 — TADP-Sec Runtime Protection

Only admitted contributors proceed to the security-classification stage.

For each admitted contributor, validated CIA requirements are reduced to a
CIA high-water level and combined with Business Impact through the TADP-Sec
policy matrix.

The admitted cohort then operates under one session-wide protection profile:

Tsession = Tmax_i  , i∈A where A is the admitted cohort.

The selected session profile is fixed before federated round 1. It is not
downgraded or dynamically changed during the session. The signed
session-security decision is valid for up to 24 hours; expiration terminates
the session and requires a new session-security decision.

A new contributor, materially changed dataset commitment, or materially
changed governance/security policy requires reassessment and formation of a
new session.

Runtime Profiles

The implementation evaluates four alternative, non-cumulative runtime
profiles.

T1 — Governed Authenticated FL

Baseline governed federated learning with:

RSA-PSS signatures;
freshness validation;
anti-replay controls;
challenge-bound PoFC participation control; and
tamper-evident audit logging.

T1 does not provide encrypted aggregation.

T2 — Modified Domingo-Ferrer + Matrix Key Switching

Research/reference protected-aggregation implementation based on:

modified Domingo-Ferrer finite-field fixed-point encryption;
encrypted client model updates and encrypted FedAvg weights;
cloud-side homomorphic multiplication and ciphertext expansion;
matrix key switching from each client-key domain to the common
authorized-aggregate-key domain; and
protected aggregation followed by final aggregate decryption only by the
authorized/classified recipient.

The final v14.0 parameterization uses:

d = 25
lambda = 10
m' = 2^80
m = 2^800
fixed-point scale 10^6

One public key-switching matrix is prepared for each fixed
client-key-to-aggregate-key relation during session setup and reused across
rounds. Matrix setup traffic is therefore excluded from recurring per-round
communication.

T3 — xMK-CKKS

Multi-key CKKS reference implementation in which:

each participating client encrypts its model update;
encrypted updates are aggregated homomorphically;
all valid session participants provide collaborative-decryption shares; and
only the resulting global aggregate is recovered.

The final v14.0 parameterization uses:

polynomial modulus degree N = 2048
total coefficient-modulus bit length 54
CKKS scale 2^40
nominal RLWE noise standard deviation 3.2

The xMK implementation uses all-participant collaborative decryption rather
than a configurable t-of-n threshold.

T4 — SAMK

Role-separated SAMK reference workflow based on:

per-client BFV protection of weighted model updates;
Paillier protection of key-dependent helper information;
protected server-side aggregation;
polynomial interpolation; and
independent aggregate recovery by authorized participating uploaders.

The final v14.0 parameterization uses:

BFV polynomial degree N = 2048
54-bit BFV coefficient modulus
BFV plaintext modulus t = 16,777,213
fixed-point scale 10^6
Paillier modulus target of approximately 3072 bits, formed from two
approximately 1536-bit primes

A client unavailable before upload does not contribute to the survivor
aggregate. An authorized client that has already uploaded may recover the
already-formed aggregate after reconnecting. Missing client updates are not
reconstructed, and the server does not obtain the plaintext aggregate.

T2--T4 are research/reference implementations used for functional,
numerical-fidelity, runtime, and generated-payload evaluation. They are not
presented as production or independently certified cryptographic deployments.

**Experimental Study
**
The reported final experiment corresponds to TADP-SEC v14.0 and uses the
canonical ULB/Kaggle credit-card-fraud dataset.

Dataset
Total transactions: 284,807
Fraud transactions: 492
Normal transactions: 284,315
Input features: 29
Federated clients: 20
Client-training records: 182,276
Validation records: 45,569
Test records: 56,962

The dataset is partitioned across non-IID clients using class-conditional
Dirichlet allocation with:

fraud-class alpha = 0.8
normal-class alpha = 1.2

A common standard scaler is fitted only on the union of client-training data
and is subsequently applied to client, validation, and test records.

The canonical experiment uses:

5 random seeds and 20 federated rounds for B0--T3;
3 random seeds and 3 rounds for the T4 SAMK feasibility study;
3 random seeds and 1 round for each protocol-enforcement test;
3 random seeds and 1 round for the T4 dropout/availability test;
2 local epochs per round;
batch size 32;
learning rate 0.01;
L2 regularization 0.005; and
sample-size-weighted FedAvg.

The final v14.0 experiment was executed on the Google Colab Free tier using a
Python 3 CPU runtime with an Intel Xeon CPU at 2.20 GHz, 1 physical core
(2 logical CPUs), 12.67 GiB of RAM, and 107.72 GiB of disk capacity.

The dataset itself is not redistributed by this repository. Users should
obtain creditcard.csv from the original ULB/Kaggle source and provide its
local path to the experiment.

**Governance Evidence in the Public-Dataset Experiment
**
The public credit-card-fraud dataset contains transaction features and labels
but does not contain organization-level governance or CIA/Business-Impact
metadata.

Therefore:

Data Quality is derived automatically from each client's actual local
data partition;
Source Reliability, Documentation, Timeliness, Regulatory, and Context are
instantiated through fixed controlled experimental archetypes; and
CIA/Business-Impact conditions are represented through fixed controlled
experimental archetypes.

Submitted evidence is validated before authoritative scoring, and the server
performs the final HPS calculation, admission decision, CIA/BI mapping, and
session-profile selection.

These archetypes are used to exercise the governance and security workflow
under reproducible heterogeneous conditions.

They do not represent real organizations and should not be interpreted as
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

TADP-Sec/
│
├── README.md
│
├── TADP-Sec_Canonical_Experiment and more results
│
├── TADP-Sec_Supplementary_Material.pdf
│
├── crypto_artifacts/
│
├── fig/
│
├── ledgers/
│
├── stats/
│
└── LICENSE
