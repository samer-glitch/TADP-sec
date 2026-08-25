# TADP-Sec v14.0 — Complete Repository Guide

Trustworthy AI Data Preparation with Governance-to-Runtime Security for Federated Learning

This file is written as a complete README-style description of the final TADP-Sec v14.0 experimental repository. It explains what is implemented, what each repository item contains, the exact final experimental design, the final v14.0 parameters and results, the scope of the security claims, and the files needed for reproducibility.

-------------------------------------------------------------------------------
1. REPOSITORY STATUS
-------------------------------------------------------------------------------

Canonical experiment version:
    TADP-SEC v14.0

Protocol version:
    TADP-SEC/14.0

Frozen governance profile:
    financial_fraud_experimental_profile_v2

Governance policy version:
    2.3-phase1-fixed-threshold-critical-floor-review-profile

Canonical dataset:
    ULB credit-card-fraud dataset

Canonical dataset SHA-256:
    76274b691b16a6c49d3f159c883398e03ccd6d1ee12d9d8ee38f4b4b98551a89

Source-code basis recorded by the v14.0 implementation:
    TADP_Sec_v13_2.py

Recorded source-code-basis SHA-256:
    56d6833fa655c7aebdd259b23d886c3b88fe76119b3f993851dc4edd39654eb4

The final v14.0 run is the manuscript-valid run. Older v11.x, v12.x, and v13.x outputs are development history and should not be mixed with the final reported values.

-------------------------------------------------------------------------------
2. WHAT TADP-SEC IMPLEMENTS
-------------------------------------------------------------------------------

TADP-Sec is a governance-to-runtime federated-learning framework. It makes two sequential decisions.

First, TADP evaluates whether a candidate contributor may participate. Governance evidence is validated and mapped to six scored dimensions. The server computes the Hybrid Provenance Score (HPS), applies non-compensatory critical-dimension safeguards, and makes the admission decision under a frozen policy.

Second, only admitted contributors proceed to TADP-Sec runtime protection. Validated confidentiality, integrity, availability, and Business Impact requirements determine each admitted client's minimum protection tier. Once the admitted cohort is closed, the server selects one common session profile equal to the highest policy-ranked admitted-client requirement. The selected profile is fixed for the session.

The implementation includes:

- canonical ULB credit-card-fraud federated-learning evaluation;
- evidence-based TADP contributor admission;
- six governance dimensions with a fixed scoring rubric;
- critical-dimension safeguards preventing weak critical evidence from being hidden by a weighted average;
- server-side HPS computation and deterministic admission decisions;
- post-admission CIA + Business Impact classification;
- one immutable session-wide runtime profile;
- T1 governed authenticated federated learning;
- T2 modified Domingo-Ferrer protected transformation with matrix key switching;
- T3 xMK-CKKS multi-key protected aggregation with collaborative decryption;
- T4 SAMK BFV/Paillier reference aggregation with independent authorized-client recovery;
- signatures/authentication, freshness, anti-replay, session/round binding, and PoFC participation control;
- numerical aggregate-fidelity gates;
- protocol-enforcement tests;
- T4 pre-upload dropout and delayed post-upload recovery tests;
- full-precision metric-equivalence diagnostics;
- governance robustness and leave-one-dimension-out analysis;
- append-only, hash-chained, tamper-evident audit ledgers with signed checkpoints and final seals;
- machine-readable CSV/JSON outputs, figures, and a unified HTML report.

T2-T4 are research/reference implementations for functionality, numerical fidelity, runtime, generated protocol-object volume, and workflow evaluation. They are not presented as production cryptographic deployments or independent cryptographic certifications.

-------------------------------------------------------------------------------
3. REPOSITORY CONTENTS
-------------------------------------------------------------------------------

The repository root is organized as follows:

    crypto_artifacts/
    figs/
    ledgers/
    stats/
    README.md
    TADP-Sec_Runtime_Mechanisms_Technical_Supplement.pdf
    TADP-Sec_Supplementary_Material_v14.pdf
    TADP_Sec_Canonical_Experiment_v14.ipynb
    TADP_Sec_v12_1_Four_Panel_2x2_600dpi.png
    TADP_Sec_v12_1_Four_Panel_2x2_vector.pdf
    all_scenarios_results_comprehensive.csv
    index.html

3.1 crypto_artifacts/

Contains cryptographic configuration and experiment-generated cryptographic/audit artifacts needed to inspect the reference implementations. Depending on the run bundle, this folder may include parameter manifests, setup commitments, public or non-secret protocol artifacts, and hashes that bind cryptographic setup to the experiment.

Private client cryptographic keys should not be treated as publication artifacts. The audit design does not require storing private cryptographic keys in the public reproducibility repository.

3.2 figs/

Contains the final publication figures generated from saved v14.0 results, including high-resolution raster and vector outputs. The final four-panel publication figure summarizes:

A. Average Precision trajectories;
B. TADP governance/admission outcomes;
C. protocol communication volume and cryptographic computation cost;
D. protocol-enforcement outcomes before and after blocking injected violations.

The v14.0 run generated 600-DPI PNG and vector-PDF figure outputs.

IMPORTANT VERSION-NAMING NOTE:
The two root-level figure names shown above still contain "v12_1". If these files are the final v14.0 figures, they should preferably be renamed before public release to avoid reviewer confusion, for example:

    TADP_Sec_v14_0_Four_Panel_2x2_600dpi.png
    TADP_Sec_v14_0_Four_Panel_2x2_vector.pdf

The numeric content, not the filename, determines whether the figure is the final v14.0 figure. A v14.0 repository should avoid retaining an older-version label on final figures.

3.3 ledgers/

Contains the tamper-evident audit layer produced by the experiment. The implementation uses logical role separation on one execution host and records:

- the central governance/runtime ledger;
- client-specific logical ledgers;
- the cryptographic ledger;
- signed checkpoints;
- final subledger seals;
- a root-of-roots commitment binding final subledger heads;
- the final central governance/runtime seal.

The ledgers are hash-chained and tamper-evident, not physically immutable. In the single-process experiment, client-specific ledgers are logically separated but stored under one results tree. This should not be described as physically distributed storage.

The audit layer records governance/runtime metadata and commitments. It does not store raw client datasets, plaintext individual client model updates, or private client cryptographic keys as audit content.

The final v14.0 run produced 22 final ledger seals.

3.4 stats/

Contains the machine-readable statistical and reproducibility outputs generated by the final run. Important files include, or are represented by, the following outputs:

- admission_results.json
- final_seed_summary.csv
- scenario_summaries_raw.csv
- publication_operational_comparison_b0_t4.csv
- publication_protocol_enforcement_attack_only.csv
- publication_samk_dropout_robustness.csv
- publication_aggregate_fidelity_diagnostics.csv
- aggregate_fidelity_diagnostics.csv
- noninferiority_ap_planned_contrasts.csv
- metric_equivalence_diagnostics_summary.csv
- metric_equivalence_diagnostics_per_seed.csv
- governance/session-tier summaries
- machine_specification.json
- resource_measurement_capabilities.json
- crypto_parameter_profile.json
- postprocessing_status.json
- TADP_Sec_Publication_Report.html
- governance_robustness/ outputs produced by the post-freeze robustness analysis

These files are the preferred source for exact numeric verification rather than values copied manually from plots.

3.5 README.md

The README should explain the repository, the canonical v14.0 status, how to run the experiment, what each folder contains, the final configuration, the major results, and the scope of the claims. This text file is written so that it can be used as the basis of that README.

3.6 TADP-Sec_Runtime_Mechanisms_Technical_Supplement.pdf

This technical supplement explains how the three protected aggregation mechanisms work at the mathematical and workflow level:

- T2 modified Domingo-Ferrer + matrix key switching;
- T3 xMK-CKKS;
- T4 SAMK.

It separates the original cryptographic ideas from their use inside TADP-Sec, explains what is encrypted, who performs each operation, who can recover the aggregate, and how a federated-learning round proceeds. It is intended as a mechanism-level explanatory document, not as a replacement for the cited cryptographic security proofs.

3.7 TADP-Sec_Supplementary_Material_v14.pdf

This is the implementation-aligned supplementary material for the final v14.0 manuscript. It contains the methodological, experimental, robustness, extended-results, and reproducibility details that do not fit in the main manuscript.

Its principal contents are:

S1. Governance Evidence, Policy, and Controlled Archetypes
S2. TADP-Sec Security Profile and Session Specification
S3. Complete Experimental and Cryptographic Configuration
S4. Governance Robustness and Ablation
S5. Extended Performance and Security Results
S6. Metric Equivalence and Reproducibility
S7. Scope and Interpretation Notes

The v14.0 supplement replaces older v11.7 supplementary values. Older supplementary PDFs should not be used for the final manuscript.

3.8 TADP_Sec_Canonical_Experiment_v14.ipynb

This is the canonical executable experiment notebook for the final release. It should contain the complete v14.0 implementation used to reproduce:

- dataset preprocessing and non-IID partitioning;
- governance evidence validation;
- HPS calculation and TADP admission;
- CIA/BI classification and tier selection;
- B0, B1, A1, T1, T2, T3, and T4 scenarios;
- attack/enforcement tests;
- T4 availability/dropout test;
- fidelity diagnostics;
- metric-equivalence diagnostics;
- audit ledgers and seals;
- CSV/JSON/HTML reporting;
- publication figures.

For exact reproducibility, this notebook should be preserved exactly as executed, together with the final result archive and machine-readable output files.

3.9 all_scenarios_results_comprehensive.csv

Contains the consolidated round-level results across the evaluated scenarios. This is the main machine-readable experiment table from which scenario summaries and publication tables are derived.

3.10 index.html

Provides the unified browser-readable TADP-Sec publication/results report. It is a convenient entry point for reviewers who want to inspect the final tables and figures without opening individual CSV files.

-------------------------------------------------------------------------------
4. FINAL V14.0 EXECUTION ENVIRONMENT
-------------------------------------------------------------------------------

All final manuscript results were obtained on Google Colab Free using a Python 3 CPU runtime with:

CPU:
    Intel(R) Xeon(R) CPU at 2.20 GHz

Physical cores:
    1

Logical CPUs:
    2

System RAM:
    12.67 GiB

Disk capacity:
    107.72 GiB

Runtime values are sequential single-host wall-clock measurements.

Protocol communication values are generated logical-role byte counts produced by the implementation. They are not network packet captures and do not include real transport latency, framing, TLS overhead, retransmissions, or data-center networking effects.

Absolute energy and carbon values are not reported because direct hardware/facility energy instrumentation was not available in the final environment. No assumption-based energy or carbon substitute is used.

-------------------------------------------------------------------------------
5. DATASET AND FEDERATED-LEARNING CONFIGURATION
-------------------------------------------------------------------------------

Dataset:
    Canonical ULB credit-card-fraud dataset

Total transactions:
    284,807

Fraud records:
    492

Normal records:
    284,315

Input features:
    29

Held-out test split:
    56,962 records
    20% of the complete dataset

Validation split:
    45,569 records
    20% of the post-test training pool

Client-training records:
    182,276

Fraud records in client-training pool:
    315

Number of candidate clients:
    20

Non-IID partitioning:
    class-conditional Dirichlet

Fraud Dirichlet alpha:
    0.80

Normal Dirichlet alpha:
    1.20

Preprocessing:
    one common StandardScaler is fitted only on the union of client-training
    records in the simulation and then applied to all client, validation, and
    test records.

Important deployment note:
    This centralized fitting of the common scaler is an experimental
    simulation convenience. A production FL deployment would require an
    appropriate federated preprocessing/statistics protocol.

Model:
    regularized logistic regression

Model coordinates:
    30 total = 29 feature weights + 1 bias

Local epochs per round:
    2

Batch size:
    32

Learning rate:
    0.01

L2 regularization:
    lambda = 0.005

Aggregation:
    sample-size-weighted FedAvg

For the valid current-round contributor set V_t:

    alpha_i = n_i / sum_j(n_j)
    Delta_t = sum_i(alpha_i * Delta_i,t)

A client removed before aggregation is excluded from the denominator.

Classification threshold:
    selected using the validation set subject to FPR <= 0.005,
    then evaluated on the held-out test set.

-------------------------------------------------------------------------------
6. TADP GOVERNANCE POLICY
-------------------------------------------------------------------------------

6.1 Governance dimensions

TADP evaluates six governance dimensions on a common 0-5 scale:

    Source Reliability (SR)
    Data Quality (DQ)
    Documentation (DOC)
    Timeliness (TIME)
    Regulatory Alignment (REG)
    Context of Use (CTX)

6.2 Frozen v14.0 weights

    SR    0.20    critical
    DQ    0.25    critical
    DOC   0.15    supporting
    TIME  0.15    supporting
    REG   0.15    critical
    CTX   0.10    critical

The weights sum to 1.0.

Critical dimensions:
    SR, DQ, REG, CTX

Supporting dimensions:
    DOC, TIME

6.3 Governance evidence model

Nontechnical governance evidence is represented by fixed, reproducible controlled archetypes because the public ULB dataset does not contain organization-level provenance, documentation, regulatory, context, or CIA/Business-Impact metadata.

Data Quality is handled differently: DQ evidence is technically derived from the actual local client partition by the Local Evidence Validator.

The controlled archetypes are experimental fixtures. They are not claims about actual organizations and are not universal governance maturity scores.

6.4 Hybrid Provenance Score

For governance dimensions d with fixed weights w_d and validated scores D_i,d:

    HPS_i = sum_d(w_d * D_i,d)

The normalized critical-dimension score is computed only over the critical set C:

    HPS_C,i = sum_(d in C)(w_d * D_i,d) / sum_(d in C)(w_d)

The critical-dimension floor is:

    C_i,min = min_(d in C)(D_i,d)

6.5 Frozen thresholds

Reject threshold:
    T_R = 3.0

Direct-acceptance threshold:
    T_A = 4.0

Automated-review critical-profile threshold:
    T_C_review = 3.5

Critical-dimension minimum:
    C_min = 3.0

Relationship:
    T_C_review = (T_R + T_A) / 2

IMPORTANT:
    There is NO separate T_C_direct threshold in v14.0.

6.6 Frozen admission rule

1. If HPS < T_R:
       AUTO_REJECT

2. If HPS >= T_R but at least one critical dimension is below C_min:
       REMEDIATION / not admitted

3. If HPS >= T_A and every critical dimension satisfies C_min:
       DIRECT_ACCEPT

4. If T_R <= HPS < T_A and every critical dimension satisfies C_min:
       automated review
       accept only if HPS_C >= T_C_review

The automated-review path uses already validated governance scores. It is not subjective rescoring and is not quota-based admission.

6.7 Final admission outcome

Candidate clients:
    20

Admitted:
    12 (60%)

Not admitted:
    8 (40%)

Directly accepted:
    6

Accepted through automated review:
    6

Auto-rejected below T_R:
    5

Routed to remediation / not admitted:
    3

Evidence hold/revoked:
    0

-------------------------------------------------------------------------------
7. GOVERNANCE-TO-SECURITY HANDOFF
-------------------------------------------------------------------------------

TADP-Sec begins after the admitted cohort has been finalized.

For each admitted client, validated confidentiality, integrity, availability, and Business Impact values determine a required policy class/tier. The session does not run a different protection profile for each client. Instead, one common session profile is selected:

    T_session = max_i(T_i), for all admitted i

where max denotes the highest policy-ranked requirement.

In the final admitted cohort, the minimum client-tier requirements were:

    T2: 3 clients
    T3: 4 clients
    T4: 5 clients

Therefore the unified session requirement was:

    C4_RESTRICTED / T4_SAMK

T1-T3 remain controlled benchmark profiles over the same admitted cohort so that cost and utility can be compared. They are alternative, non-cumulative profiles and are not dynamically stacked inside one session.

The session-security decision is fixed before federated round 1 and is not downgraded during the session. The signed decision is valid for up to 24 hours. If it expires, the session is terminated and a new session-security decision is required.

-------------------------------------------------------------------------------
8. RUNTIME PROTECTION PROFILES
-------------------------------------------------------------------------------

8.1 T1 — Governed Baseline

T1 is governed plain FL with runtime protocol controls rather than encrypted aggregation.

Implemented controls include:

- authenticated/session-bound submissions;
- freshness checks;
- replay/staleness rejection;
- PoFC challenge-bound participation control;
- audit logging.

PoFC is used to bind participation to server-issued session/round challenges and enforce participation limits. It is not claimed to be a general network-level denial-of-service defense.

8.2 T2 — Modified Domingo-Ferrer + Matrix Key Switching

T2 uses the modified Domingo-Ferrer protected transformation with matrix key switching.

Final v14.0 parameters:

    d = 25
    lambda = 10
    m' = 2^80
    m = (m')^lambda = 2^800
    fixed-point scale = 10^6

For each fixed client-key -> authorized aggregate-key relation, one public switching matrix M_i is prepared once before round 1 and reused throughout that session/seed.

Per protected round:

1. The client locally trains and forms its model update.
2. The client encrypts the model update under the modified DF construction.
3. The client also encrypts its FedAvg scalar weight.
4. The logical cloud receives the encrypted update and encrypted scalar.
5. The cloud performs the required homomorphic multiplication/expansion.
6. The cloud applies the cached public key-switching matrix after multiplication.
7. The cloud adds the switched protected contributions.
8. The final aggregate ciphertext is delivered to the designated authorized/classified role.
9. Only that authorized role decrypts the final aggregate.
10. The recovered global model is distributed normally to the participating clients.

The one-time switching-matrix setup is excluded from recurring protocol communication. The per-round application of key switching is included in cryptographic computation time.

T2 is a proof-of-concept. The underlying DF family is a legacy symmetric-key homomorphic construction with known security limitations, including known-plaintext concerns. T2 is not assigned the same standardized security claim as T3 or T4.

8.3 T3 — xMK-CKKS Multi-Key Protected Aggregation

Final v14.0 xMK-CKKS parameters:

    polynomial modulus degree N = 2048
    total coefficient-modulus bits = 54
    CKKS scale = 2^40
    nominal RLWE noise standard deviation = 3.2
    collaborative decryption-share noise standard deviation = 8.0
    secret distribution = dense uniform ternary {-1, 0, 1}

The N=2048 / 54-bit coefficient-modulus profile is configured against the Microsoft SEAL tc128 parameter bound. The custom xMK implementation is a research reference implementation and is not independently certified.

Per session/seed:

1. Each participating client owns its own secret/public key pair.
2. Participant public keys form the aggregate public key.
3. The setup is performed once and reused across rounds.

Per protected round:

1. Each client packs and encrypts its weighted model update.
2. The server homomorphically adds client ciphertexts.
3. The server distributes the aggregate ciphertext component required for collaborative decryption.
4. Each valid participant returns an aggregate-bound partial decryption share.
5. The shares are combined to recover only the global aggregate.

The implementation requires all valid session shares. It is not a configurable t-of-n threshold decryption scheme.

8.4 T4 — SAMK BFV + Paillier Reference Workflow

T4 follows the SAMK multi-key secure-aggregation workflow using BFV, Paillier-protected helper information, and polynomial interpolation.

Final v14.0 reference parameters:

    BFV polynomial modulus degree N = 2048
    BFV coefficient modulus bit length = 54
    BFV q = 18014398509404161
    BFV plaintext modulus t = 16777213
    fixed-point scale = 10^6
    nominal BFV/RLWE noise standard deviation = 3.2
    secret distribution = dense uniform ternary {-1, 0, 1}
    Paillier prime size target ~= 1536 bits each
    Paillier modulus target ~= 3072 bits

The BFV/RLWE parameter profile and the approximately 3072-bit Paillier target correspond to approximately 128-bit classical security categories. The custom Python implementation itself is not independently certified and should not be described as a production cryptosystem.

Per client i, the weighted update is:

    u_i = alpha_i * Delta_i

The client BFV-encrypts u_i under its own key. If the BFV ciphertext has component c_i,1(X) and the client secret key is s_i, the client forms the helper polynomial:

    f_i(X) = s_i * c_i,1(X)

The helper polynomial is evaluated at public interpolation points.

- The first N-1 helper values are Paillier-encrypted for the server.
- The final helper value is separately encrypted for each authorized recipient.

The server:

1. aggregates the BFV c0 components;
2. aggregates the Paillier-protected helper values;
3. decrypts only the first N-1 aggregate helper points;
4. retains the final aggregate helper point encrypted separately for each recipient.

Each authorized uploader:

1. decrypts its own final aggregate helper point;
2. combines it with the N-1 server-recovered helper points;
3. interpolates the aggregate helper polynomial;
4. recovers the same combined weighted FedAvg update.

The server does not obtain the plaintext aggregate in the evaluated honest-but-curious, non-colluding server model.

The single-process experimental harness may mirror one already validated authorized-client recovery only to advance the global model. This is an implementation harness step and is not server-side plaintext recovery.

T4 dropout semantics are important:

- a client unavailable before upload contributes no update;
- its missing update is NOT reconstructed;
- the survivor FedAvg denominator is recomputed using current valid uploaders;
- a client that completed upload and later became temporarily unavailable can recover the same already-formed aggregate after reconnecting.

-------------------------------------------------------------------------------
9. EXPERIMENTAL RUN DESIGN
-------------------------------------------------------------------------------

Main B0-T3 controlled comparison:
    5 seeds x 20 rounds

T4 SAMK feasibility/reference study:
    3 seeds x 3 rounds

Protocol-enforcement tests:
    3 seeds x 1 round

T4 availability/dropout study:
    3 seeds x 1 round
    2 pre-upload dropouts per run
    delayed post-upload recovery exercised

Cohorts:

    B0 and B1:
        all 20 candidate clients

    A1 and T1-T4:
        same fixed 12-client TADP-admitted cohort

T4 uses the shorter three-round horizon because its pure-Python SAMK reference path is substantially more computationally expensive than the other profiles.

-------------------------------------------------------------------------------
10. SCENARIO DEFINITIONS
-------------------------------------------------------------------------------

B0_Plain_FL
    Plain federated learning over all 20 clients.

B1_xMK_CKKS
    xMK-CKKS over the same 20-client non-governed cohort. This isolates the cryptographic path from the TADP admission effect.

A1_TADP_admission_only
    TADP governance/admission only. Uses the frozen 12-client admitted cohort without TADP-Sec runtime protection mechanisms.

T1_Plain_TADP
    Governed baseline over the fixed admitted cohort with authentication, freshness, anti-replay, PoFC, and audit controls.

T2_DF_KS_TADP
    Governed admitted cohort using the modified DF + matrix key-switching protected transformation.

T3_XMK_CKKS_TADP
    Governed admitted cohort using xMK-CKKS multi-key protected aggregation and all-participant collaborative decryption.

T4_SAMK_TADP
    Governed admitted cohort using the SAMK BFV/Paillier reference workflow. Evaluated as a separate 3-seed x 3-round feasibility/reference study.

T1_TEST_SIGNATURE_ATTACK
    Injected invalid-signature submissions.

T2_TEST_REPLAY_ATTACK
    Injected replay/stale submission.

T3_TEST_POFC_ATTACK
    Injected PoFC participation overflow.

T4_TEST_DROPOUT
    Dedicated SAMK availability test with two pre-upload non-uploaders and one delayed post-upload recipient recovery per run.

-------------------------------------------------------------------------------
11. FINAL PREDICTIVE-UTILITY RESULTS
-------------------------------------------------------------------------------

Final v14.0 utility values:

Scenario            Seeds x Rounds    Final AP              AP reference difference       Final F1              Final MCC
--------------------------------------------------------------------------------------------------------------------------
B0 Plain FL         5 x 20            0.7280 +/- 0.0002     --                            0.7197 +/- 0.0000     0.7311 +/- 0.0000
B1 xMK-CKKS         5 x 20            0.7280 +/- 0.0002      0 vs B0                       0.7197 +/- 0.0000     0.7311 +/- 0.0000
A1 TADP             5 x 20            0.7267 +/- 0.0003     -0.0013 vs B0                  0.7186 +/- 0.0026     0.7276 +/- 0.0022
T1 Plain TADP       5 x 20            0.7267 +/- 0.0003      0 vs A1                       0.7186 +/- 0.0026     0.7276 +/- 0.0022
T2 DF+KS            5 x 20            0.7267 +/- 0.0003     +4.93e-09 vs T1                0.7186 +/- 0.0026     0.7276 +/- 0.0022
T3 xMK-CKKS         5 x 20            0.7267 +/- 0.0003     -9.62e-10 vs T1                0.7186 +/- 0.0026     0.7276 +/- 0.0022
T4 SAMK             3 x 3             0.7218 +/- 0.0010     -2.18e-07 vs matched T1 R3     0.7219 +/- 0.0209     0.7314 +/- 0.0190

Interpretation:

- B1 matched B0 at the reported metric precision.
- T1 matched A1.
- T2 and T3 introduced only negligible full-precision AP differences relative to T1 and no F1, MCC, or final binary-prediction differences.
- T4 is not compared as a 20-round endpoint because it uses a separate 3-round feasibility horizon; it is compared descriptively with matched T1 round-3 trajectories.
- The primary utility-preservation claim is about similarity to the corresponding plain reference, not about one profile outperforming another.

-------------------------------------------------------------------------------
12. FINAL OPERATIONAL-COST RESULTS
-------------------------------------------------------------------------------

All scenarios use a 0.240-KB plaintext model-update representation per client.

Scenario            Plain/client KB   Ciphertext/client KB   Protocol comm./round KB   Crypto time/round s   Setup/seed ms   Runtime/seed s
--------------------------------------------------------------------------------------------------------------------------------------------
B0 Plain FL         0.240             --                     9.60                      0.00                  0.00            19.6
B1 xMK-CKKS         0.240             28.67                  1151.68                   10.86                 3522.58         240.6
A1 TADP             0.240             --                     5.76                      0.00                  0.00            10.8
T1 Plain TADP       0.240             --                     5.76                      0.00                  0.00            22.9
T2 DF+KS            0.240             75.00                  1007.88                   4.21                  514.35          108.4
T3 xMK-CKKS         0.240             28.67                  691.01                    6.57                  1983.26         156.6
T4 SAMK             0.240             1609.98                19697.01                  1145.78               133188.82       3574.4

Definitions:

Protocol communication/round
    Recurring logical uplink plus downlink per training round.

B0/A1/T1 communication includes:
    client update uploads + global-model distribution.

T2 communication includes:
    encrypted model-update submissions + encrypted FedAvg scalar weights in the
    uplink + post-KS aggregate ciphertext delivery + normal global-model
    distribution.

B1/T3 communication includes:
    xMK ciphertext uploads + distribution of the aggregate ciphertext component
    needed for collaborative decryption + returned partial-decryption shares +
    global-model distribution.

T4 communication includes:
    BFV/Paillier-protected uploads + recipient-specific recovery data.

One-time setup:
    T2 switching matrices, xMK public-key/session setup, and SAMK BFV/Paillier
    keys are generated before round 1 and reused during the seed/session.
    Their setup traffic is excluded from recurring communication.

Crypto time/round:
    measured wall-clock time of the complete protected cryptographic path.
    It excludes one-time setup, local training, model evaluation, and network
    latency.

Runtime/seed:
    end-to-end wall-clock time for one independent run, including setup and all
    federated rounds.

The cost ordering is mechanism-dependent rather than monotonic with tier number. T1-T4 are different mechanisms, not cumulative layers.

-------------------------------------------------------------------------------
13. PROTECTED-AGGREGATION FIDELITY
-------------------------------------------------------------------------------

Protected aggregates are compared with an experiment-side plaintext FedAvg reference using:

- maximum absolute coordinate error;
- root-mean-squared error (RMSE).

Both scenario-specific gates must pass. Relative L2 is diagnostic only and is not an acceptance gate.

Fidelity gates:

Scenario            Max-absolute gate      RMSE gate
-----------------------------------------------------
B1 xMK-CKKS         2.00e-04               5.00e-05
T2 DF+KS            2.00e-06               5.00e-07
T3 xMK-CKKS         2.00e-04               5.00e-05
T4 SAMK             1.00e-04               1.00e-04

Final fidelity results:

Scenario            Checks      Max abs. error    Mean RMSE      Max RMSE       Result
----------------------------------------------------------------------------------------
B1 xMK-CKKS         100/100     4.29e-07          9.64e-08       1.39e-07       PASS
T2 DF+KS            100/100     9.64e-07          1.30e-07       2.06e-07       PASS
T3 xMK-CKKS         100/100     3.32e-07          5.52e-08       8.68e-08       PASS
T4 SAMK             9/9         4.24e-06          1.04e-06       1.26e-06       PASS

T4 also passed:
    108/108 authorized-recipient decryptions

These gates are numerical acceptance criteria for the reference implementations. They are not formal cryptographic security proofs or generic HE precision guarantees.

-------------------------------------------------------------------------------
14. PROTOCOL-ENFORCEMENT TESTS
-------------------------------------------------------------------------------

Each attack test was executed using 3 seeds x 1 round.

Profile    Injected violation      Injected    Blocked    Benign blocked    Effective clients
---------------------------------------------------------------------------------------------
T1         Invalid signature       2           2/2        0                 10
T2         Replay/stale update     1           1/1        0                 11
T3         PoFC overflow           3           3/3        0                 9

All injected protocol violations were rejected before aggregation, and no violating update was aggregated.

The tests demonstrate enforcement of the implemented:

- signature/authentication controls;
- freshness and anti-replay controls;
- challenge-bound PoFC participation controls.

They do NOT establish general robustness against:

- semantic data poisoning;
- model poisoning;
- backdoor attacks;
- arbitrary Byzantine behavior;
- colluding malicious clients;
- general network-level denial-of-service attacks.

-------------------------------------------------------------------------------
15. T4 AVAILABILITY / DROPOUT RESULTS
-------------------------------------------------------------------------------

Run design:
    3 seeds x 1 round

Pre-upload unavailable clients per run:
    2

Final valid contributors per run:
    10

Delayed post-upload recipient recovery:
    3/3 successful

All authorized recipients passed:
    Yes

Protected aggregate fidelity passed:
    Yes

Selected T4 profile downgraded:
    No

Server obtained plaintext aggregate:
    No

Interpretation:

A pre-upload unavailable client contributes no model update and is excluded from the survivor aggregate. The experiment does not reconstruct the missing client's update.

A client that completed its upload before becoming temporarily unavailable can later recover the same already-formed aggregate package after reconnecting.

The test demonstrates an availability property of the reference SAMK workflow. It is not a production service-level availability guarantee.

-------------------------------------------------------------------------------
16. FULL-PRECISION METRIC-EQUIVALENCE DIAGNOSTICS
-------------------------------------------------------------------------------

The implementation stores full-precision comparisons because rounded AP/F1/MCC can hide small numerical changes introduced by protected aggregation.

Final mean AP differences:

    B1 vs B0        0.0000000000e+00
    T1 vs A1        0.0000000000e+00
    T2 vs T1       +4.9281174030e-09
    T3 vs T1       -9.6226779878e-10
    T4 vs T1(R3)   -2.1793075740e-07

Maximum absolute F1 difference:
    0 for all planned reference comparisons

Maximum absolute MCC difference:
    0 for all planned reference comparisons

Maximum binary prediction disagreement count:
    0 for all planned reference comparisons

Mean final-model parameter L2 differences:

    B1 vs B0        9.5080355737e-07
    T1 vs A1        0
    T2 vs T1        1.7181445032e-06
    T3 vs T1        6.3774152703e-07
    T4 vs T1(R3)    8.5997910798e-06

Maximum test-probability absolute differences:

    B1 vs B0        9.3019284937e-07
    T1 vs A1        0
    T2 vs T1        2.0256355668e-06
    T3 vs T1        1.2982329682e-06
    T4 vs T1(R3)    2.8004374250e-05

Thus the protected models are not claimed to be numerically identical to the plaintext references. Instead, the observed perturbations were small enough that final F1, MCC, and binary test predictions remained unchanged in the evaluated comparisons.

-------------------------------------------------------------------------------
17. AP NON-INFERIORITY OUTPUT
-------------------------------------------------------------------------------

The implementation contains a frozen AP non-inferiority margin:

    delta = 0.005

The planned five-seed contrasts are:

    B1 vs B0
    A1 vs B0
    T1 vs A1
    T2 vs T1
    T3 vs T1

T4 is excluded from the planned five-seed paired non-inferiority table because T4 uses a separate 3-seed x 3-round feasibility horizon. T4 is reported descriptively against the matched T1 round-3 trajectory instead.

The machine-readable planned output is:

    stats/noninferiority_ap_planned_contrasts.csv

-------------------------------------------------------------------------------
18. GOVERNANCE ROBUSTNESS AND ABLATION
-------------------------------------------------------------------------------

The robustness analysis is post-freeze and does not change the canonical policy.

The analysis:

- loads saved v14.0 validated admission records;
- replays the frozen baseline policy;
- verifies that the replay reproduces the stored binary decisions;
- perturbs thresholds only for sensitivity analysis;
- perturbs one governance weight at a time;
- performs leave-one-dimension-out ablation;
- does not rescore evidence;
- does not revalidate evidence;
- does not rerun federated training;
- does not permanently change the frozen policy.

Baseline:
    12 admitted

Joint T_R/T_A threshold perturbation:

    -30% -> 12 admitted
    -20% -> 12 admitted
    -10% -> 12 admitted
      0% -> 12 admitted
    +10% -> 6 admitted
    +20% -> 6 admitted
    +30% -> 3 admitted

One-at-a-time weight sensitivity:

- Reducing the DQ weight by 30% reduced admission from 12 to 11.
- All other tested one-at-a-time weight changes at +/-10%, +/-20%, and +/-30% retained 12 admitted clients.

Leave-one-dimension-out (LODO):

- removing DQ reduced admission from 12 to 6;
- DQ removal caused 6 admission flips;
- mean |Delta HPS| after DQ removal = 0.505;
- removing any other one dimension left 12 clients admitted.

These are cohort-specific robustness observations for the frozen v14.0 experimental fixture. They do not establish a universal ranking of governance dimensions.

-------------------------------------------------------------------------------
19. AUDIT AND REPRODUCIBILITY SCOPE
-------------------------------------------------------------------------------

The v14.0 implementation records the information needed to reconstruct the reported decisions and verify the experiment, including:

- experiment version;
- protocol version;
- dataset identity and commitment information;
- dataset partition configuration;
- governance-policy identifier and version;
- evidence-validation outcomes;
- governance dimension scores;
- HPS and normalized critical HPS;
- critical-dimension minimum;
- admission decision and review disposition;
- CIA/Business-Impact classification;
- required client class/tier;
- session-wide tier decision;
- aggregate-fidelity diagnostics;
- attack/enforcement outcomes;
- T4 availability/dropout results;
- metric-equivalence diagnostics;
- AP non-inferiority outputs;
- hash-chained ledger records;
- signed checkpoints;
- final seals.

The final v14.0 archive should preserve:

1. the exact executed notebook/source;
2. the complete results directory;
3. all machine-readable CSV/JSON outputs;
4. the HTML report;
5. all publication figures;
6. the ledgers and final seals;
7. audit and cryptographic manifests;
8. the v14.0 supplementary material;
9. the runtime-mechanisms technical supplement.

-------------------------------------------------------------------------------
20. HOW TO REPRODUCE THE FINAL EXPERIMENT
-------------------------------------------------------------------------------

Recommended reproduction procedure:

1. Obtain the canonical ULB credit-card-fraud CSV.

2. Verify that the dataset matches the canonical SHA-256:

       76274b691b16a6c49d3f159c883398e03ccd6d1ee12d9d8ee38f4b4b98551a89

3. Open:

       TADP_Sec_Canonical_Experiment_v14.ipynb

   in Google Colab using a CPU runtime.

4. Do not mix artifacts from older experiment folders. Use a fresh dedicated v14.0 output directory.

5. Run the notebook from start to finish without changing the frozen governance policy, cryptographic parameters, seed lists, or run horizons if exact manuscript reproduction is intended.

6. Confirm startup metadata reports:

       TADP-SEC v14.0
       TADP-SEC/14.0

7. Confirm the canonical experiment uses:

       B0-T3: 5 seeds x 20 rounds
       T4:    3 seeds x 3 rounds
       attacks: 3 seeds x 1 round
       T4 dropout: 3 seeds x 1 round

8. Confirm TADP admission gives:

       12 admitted / 20 total
       6 direct accept
       6 automated-review accept
       5 reject
       3 remediation

9. Confirm the admitted client tier mix is:

       T2: 3
       T3: 4
       T4: 5

   and that the unified session requirement is T4.

10. Confirm all protected aggregate-fidelity checks pass.

11. Confirm all injected protocol violations are blocked before aggregation.

12. Confirm the T4 availability test retains the T4 profile, excludes pre-upload non-uploaders, and passes delayed recovery.

13. Confirm the final publication tables match the values in Sections 11-15 of this README.

14. Archive the final output tree and compute hashes for the exact executed notebook/source and final release artifacts.

-------------------------------------------------------------------------------
21. IMPORTANT CLAIM BOUNDARIES
-------------------------------------------------------------------------------

The repository supports the following claims within the evaluated design:

- governance evidence can be validated and converted into deterministic admission decisions under a fixed policy;
- critical-dimension floors can prevent weak critical dimensions from being masked by the overall weighted HPS;
- admitted-client CIA/Business-Impact requirements can be mapped to a fixed session protection profile;
- T1-T4 can be implemented as alternative runtime profiles;
- the evaluated protected aggregation paths preserve the predictive characteristics of their corresponding plaintext references within the reported experiments;
- protected aggregates satisfy the predefined numerical fidelity gates;
- the injected invalid-signature, replay/staleness, and PoFC-overflow protocol violations are blocked before aggregation;
- the evaluated T4 reference workflow supports the tested pre-upload dropout and delayed post-upload recovery behavior without tier downgrade;
- the implemented audit layer provides tamper-evident governance/runtime traceability.

The repository does NOT by itself establish:

- that the complete trained AI system is universally or fully "trustworthy" in every responsible-AI dimension;
- production-grade cryptographic certification;
- semantic poisoning robustness;
- arbitrary Byzantine robustness;
- backdoor resistance;
- general network DoS resistance;
- universal optimality of the governance weights or thresholds;
- production service-level availability;
- physical distribution of the logical audit ledgers;
- direct measured network throughput/latency;
- measured absolute energy or carbon footprint.

-------------------------------------------------------------------------------
22. SUPPLEMENTARY DOCUMENT RELATIONSHIP
-------------------------------------------------------------------------------

The two supplementary documents serve different purposes.

TADP-Sec_Supplementary_Material_v14.pdf
    Provides experiment-aligned methodological and numerical detail:
    governance policy, controlled archetypes, complete configuration,
    robustness, extended results, fidelity, enforcement, T4 availability,
    metric-equivalence, and reproducibility.

TADP-Sec_Runtime_Mechanisms_Technical_Supplement.pdf
    Provides mechanism-level mathematical and workflow explanation of T2, T3,
    and T4. It explains how protected aggregation is performed and which role
    handles each cryptographic operation.

Together, the main manuscript + v14 supplementary material + technical runtime-mechanisms supplement + exact executable notebook + machine-readable results form the complete publication/reproducibility package.


-------------------------------------------------------------------------------
END OF COMPLETE TADP-SEC v14.0 REPOSITORY README
-------------------------------------------------------------------------------
