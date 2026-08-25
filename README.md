# TADP-Sec

## Trustworthy AI Data Preparation with Governance-to-Runtime Security for Federated Learning

TADP-Sec is a research framework that connects evidence-based
data/contributor governance with runtime protection selection in Federated
Learning (FL).

The framework extends Trustworthy AI Data Preparation (TADP) through a
governance-to-security workflow in which:

- contributor evidence is validated;
- governance dimensions are scored under a fixed, versioned policy;
- admissibility is determined using the overall Hybrid Provenance Score
  (HPS), a normalized critical-dimension HPS (`HPS_C`), and a
  non-compensatory critical-dimension floor;
- only admitted contributors proceed to TADP-Sec;
- confidentiality, integrity, availability (CIA), and Business Impact (BI)
  determine each admitted client's minimum runtime protection requirement; and
- one common session protection profile, equal to the highest policy-ranked
  admitted-client requirement, is selected before federated round 1 and
  remains fixed for the lifetime of the session.

This repository contains the implementation, experimental outputs,
reproducibility artifacts, and supplementary material accompanying the
TADP-Sec study.

---

## Framework Overview

TADP-Sec separates two decisions:

1. **TADP governance admission:** whether a contribution is sufficiently
   governed to participate.
2. **TADP-Sec runtime protection:** how the admitted federation should be
   protected during training.

Governance admission is completed before CIA/BI-based runtime protection
selection.

---

## Stage 1 — TADP Governance and Admission

Clients do not provide authoritative HPS values, admission decisions, or
runtime protection tiers.

Raw-data-dependent evidence, including Data Quality evidence, is derived from
the governed local dataset. Non-technical governance conditions are supplied
as evidence-supported inputs. After evidence validation, the server-side
governance logic derives the authoritative dimension scores and admission
decision.

The experimental policy uses six governance dimensions:

- Source Reliability
- Data Quality
- Documentation
- Timeliness
- Regulatory
- Context

The overall governance score is the **Hybrid Provenance Score (HPS)**.

Four dimensions are treated as critical:

- Source Reliability
- Data Quality
- Regulatory
- Context

The admission policy therefore considers:

- overall HPS;
- normalized critical HPS (`HPS_C`); and
- the minimum score among the critical dimensions.

For the frozen `financial_fraud_experimental_profile_v2` policy:

```text
T_R        = 3.0
T_A        = 4.0
T_C_review = 3.5
C_min      = 3.0

There is no separate T_C_direct threshold in the final v14.0 policy.

Direct acceptance requires:

HPS >= T_A
and
critical_min >= C_min

For contributors in the review band:

T_R <= HPS < T_A

acceptance additionally requires:

critical_min >= C_min
and
HPS_C >= T_C_review

The resulting policy routes contributions to:

direct acceptance;
deterministic automated-review acceptance;
remediation; or
rejection.

The admission policy is fixed and versioned. It does not rank clients against
one another and does not impose a predetermined admission quota.

Stage 2 — TADP-Sec Runtime Protection

Only admitted contributors proceed to the runtime security-classification
stage.

For each admitted contributor, validated confidentiality, integrity, and
availability requirements are reduced to a CIA high-water value:

h_i = max(C_i, I_i, A_i)

The CIA high-water value is combined with Business Impact through the
TADP-Sec policy matrix to determine that client's minimum protection class
and runtime tier.

For the closed admitted cohort A, the server selects one common session
profile:

T_session = max_{i in A} T_i

The selected profile is fixed before federated round 1. It is not downgraded
or dynamically changed during the active session.

The signed session-security decision is valid for up to 24 hours. If it
expires, the session is terminated and a new session-security decision is
required.

A new contributor, a materially changed dataset commitment, or a materially
changed governance/security policy requires reassessment and formation of a
new session rather than modification of the active session.

The T1--T4 tier numbering represents policy rank. It should not be
interpreted as a claim that cryptographic strength, communication cost, or
runtime increases monotonically from T1 to T4.

Runtime Profiles

The implementation evaluates four alternative, non-cumulative runtime
profiles.

T1 — Governed Authenticated FL

T1 provides governed plain federated learning with:

RSA-PSS signatures;
authenticated and session-bound submissions;
freshness validation;
anti-replay controls;
challenge-bound PoFC participation control; and
tamper-evident audit logging.

The implementation uses 3072-bit RSA signing keys.

T1 does not provide encrypted aggregation.

T2 — Modified Domingo-Ferrer + Matrix Key Switching

T2 is a research/reference protected-aggregation implementation based on:

modified Domingo-Ferrer finite-field fixed-point encryption;
client-side encryption of the local model update;
client-side encryption of the FedAvg scalar weight;
cloud-side homomorphic multiplication and ciphertext expansion;
matrix key switching from each client-key domain to a common
authorized-aggregate-key domain;
protected addition of the transformed client contributions; and
final aggregate decryption only by the authorized/classified recipient.

The final v14.0 parameterization uses:

d                 = 25
lambda            = 10
m'                = 2^80
m                 = 2^800
fixed-point scale = 10^6

One public key-switching matrix M_i is prepared during session setup for each
fixed client-key-to-authorized-aggregate-key relation and reused across
federated rounds.

The matrices are therefore one-time session material. Their setup traffic is
excluded from recurring per-round protocol communication, while the actual
key-switching operation performed during each protected round is included in
the measured cryptographic computation.

T2 is retained as a proof-of-concept/reference implementation. The modified
Domingo-Ferrer construction is a legacy symmetric-key homomorphic scheme and
is not assigned the same 128-bit security claim as the RLWE-based T3/T4
parameter profiles.

T3 — xMK-CKKS

T3 implements an RLWE-based multi-key CKKS reference workflow in which:

each participating client encrypts its model update under its client key;
the server homomorphically aggregates the encrypted updates;
the aggregate ciphertext component required for collaborative decryption is
distributed to the participants;
all valid session participants return collaborative-decryption shares; and
the resulting global aggregate is recovered without exposing individual
plaintext client updates to the server.

The final v14.0 parameterization uses:

polynomial modulus degree N = 2048
total coefficient-modulus bits = 54
CKKS scale = 2^40
nominal RLWE noise standard deviation = 3.2

The current xMK implementation uses all-participant collaborative
decryption rather than a configurable t-of-n threshold.

The N=2048, 54-bit coefficient-modulus profile follows the Microsoft SEAL
tc128 parameter bound used by the study. The custom xMK implementation is a
research reference implementation and is not independently certified.

T4 — SAMK

T4 implements a role-separated SAMK reference workflow combining BFV,
Paillier, and polynomial interpolation.

The implemented flow includes:

an independent BFV key pair for each client;
BFV protection of each client's weighted model update;
construction of key-dependent helper information;
Paillier protection of helper evaluations;
protected server-side aggregation;
client-specific recovery information; and
independent aggregate recovery by authorized participating uploaders.

The server does not receive the plaintext individual updates and does not
recover the plaintext aggregate under the evaluated honest-but-curious,
non-colluding-server workflow.

The final v14.0 parameterization uses:

BFV polynomial degree N       = 2048
BFV coefficient modulus bits = 54
BFV plaintext modulus t      = 16,777,213
fixed-point scale            = 10^6
Paillier modulus target      ≈ 3072 bits
Paillier prime size          ≈ 1536 bits each

The BFV parameter profile follows the N=2048, 54-bit Microsoft SEAL
tc128 parameter bound used by the study. The Paillier component targets an
approximately 3072-bit modulus. These are parameter targets for the custom
reference implementation and do not constitute independent cryptographic
certification.

T4 dropout semantics

A client unavailable before upload does not contribute an update to the
survivor aggregate. The FedAvg aggregation is formed from the clients that
actually contributed.

A client that successfully uploaded but becomes temporarily unavailable
during recovery may reconnect and recover the same already-formed aggregate
package.

Missing client updates are not reconstructed.

The selected T4 policy profile is not downgraded because of the tested
dropout condition, and the server does not obtain the plaintext aggregate.

Cryptographic Scope

T2--T4 are research/reference implementations used to evaluate:

protocol functionality;
numerical fidelity;
runtime;
generated protocol-object volume; and
governance-to-runtime integration.

They are not presented as production-ready or independently certified
cryptographic deployments.

Experimental Study

The final reported experiment corresponds to TADP-SEC v14.0 and uses the
canonical ULB/Kaggle credit-card-fraud dataset.

Dataset
Total transactions       : 284,807
Fraud transactions       : 492
Normal transactions      : 284,315
Input features            : 29
Federated clients         : 20
Client-training records   : 182,276
Validation records        : 45,569
Test records              : 56,962

The training data are partitioned across non-IID clients using
class-conditional Dirichlet allocation:

fraud-class alpha  = 0.8
normal-class alpha = 1.2

A shared standard scaler is fitted only on the union of client-training
records in the experimental simulation and then applied to the client,
validation, and test records.

This shared-scaler procedure provides consistent model coordinates without
validation/test leakage. A production FL deployment would require an
appropriate federated preprocessing protocol rather than centralized access
to the union of client-training records.

Federated Configuration

The canonical experiment uses:

B0--T3                  : 5 seeds × 20 rounds
T4 SAMK feasibility     : 3 seeds × 3 rounds
Protocol-enforcement    : 3 seeds × 1 round per test
T4 dropout/availability : 3 seeds × 1 round
Local epochs            : 2 per round
Batch size              : 32
Learning rate           : 0.01
L2 regularization       : 0.005
Aggregation             : sample-size-weighted FedAvg

T4 is intentionally evaluated over a shorter horizon because the pure-Python
SAMK reference workflow is substantially more computationally expensive than
the other profiles.

Execution Environment

The final v14.0 manuscript run was executed on the Google Colab Free tier
using:

Runtime        : Python 3 CPU
CPU            : Intel Xeon, 2.20 GHz
Physical cores : 1
Logical CPUs   : 2
RAM            : 12.67 GiB
Disk capacity  : 107.72 GiB

All roles in the reference experiment execute on the same Colab node.
Accordingly, reported communication values represent generated
protocol-level byte counts between logical roles, not measured physical
network traffic.

Absolute energy or carbon consumption is not reported because direct hardware
energy instrumentation was unavailable for the final run.

Dataset Availability

The dataset itself is not redistributed by this repository.

Users should obtain creditcard.csv from the original ULB/Kaggle source and
provide its local path to the experiment.

Only a dataset matching the canonical experimental dataset should be described
as an exact reproduction of the reported full-dataset experiment.

Governance Evidence in the Public-Dataset Experiment

The public credit-card-fraud dataset contains transaction features and labels
but does not provide organization-level governance or CIA/Business-Impact
metadata.

Therefore, in the controlled experiment:

Data Quality evidence is derived automatically from each client's actual
local partition;
Source Reliability, Documentation, Timeliness, Regulatory, and Context
conditions are instantiated through fixed controlled governance archetypes;
and
CIA/Business-Impact conditions are instantiated through fixed controlled
security/risk archetypes.

The Local Evidence Validator derives raw-data-dependent technical evidence.
The server-side evidence-verification and governance logic validates the
available evidence, maps validated conditions through the frozen rubric, and
computes the authoritative:

dimension scores;
overall HPS;
normalized critical HPS (HPS_C);
minimum critical-dimension score;
admission decision;
CIA/BI security classification; and
session-profile decision.

Unsupported evidence does not receive positive evidentiary credit.

The controlled archetypes are used to exercise the complete governance and
runtime-security workflow under reproducible heterogeneous conditions.

They do not represent real organizations and should not be interpreted as
estimates of the prevalence of governance or security profiles in real-world
deployments.

Final v14.0 Governance Outcome

Under the frozen governance policy:

Candidate contributors               : 20
Admitted contributors                : 12 (60%)
Not admitted                         : 8 (40%)

Directly accepted                    : 6
Accepted after automated review      : 6
Rejected below T_R                   : 5
Routed to remediation                : 3

Among the 12 admitted clients, the minimum runtime requirements were:

T2 requirement : 3 clients
T3 requirement : 4 clients
T4 requirement : 5 clients

The highest-ranked admitted-client requirement was therefore T4, making
T4 the unified session-level policy requirement for this controlled cohort.

T1--T3 are retained as benchmark profiles over exactly the same admitted
cohort. They do not represent alternative profiles dynamically selected
during the reported T4-governed session.

Final v14.0 Predictive Results
Scenario	Run design	Final AP	Reference	Delta AP	Final F1	Final MCC
B0 Plain FL	5 × 20	0.7280 ± 0.0002	--	--	0.7197 ± 0.0000	0.7311 ± 0.0000
B1 xMK-CKKS	5 × 20	0.7280 ± 0.0002	B0	0.0000	0.7197 ± 0.0000	0.7311 ± 0.0000
A1 TADP	5 × 20	0.7267 ± 0.0003	B0	-0.0013	0.7186 ± 0.0026	0.7276 ± 0.0022
T1 Plain TADP	5 × 20	0.7267 ± 0.0003	A1	0.0000	0.7186 ± 0.0026	0.7276 ± 0.0022
T2 DF+KS	5 × 20	0.7267 ± 0.0003	T1	+4.93e-9	0.7186 ± 0.0026	0.7276 ± 0.0022
T3 xMK-CKKS	5 × 20	0.7267 ± 0.0003	T1	-9.62e-10	0.7186 ± 0.0026	0.7276 ± 0.0022
T4 SAMK	3 × 3	0.7218 ± 0.0010	T1 at R3	-2.18e-7	0.7219 ± 0.0209	0.7314 ± 0.0190

B1 matched B0 at the reported predictive-metric precision. T1 matched A1,
while T2 and T3 introduced only negligible AP differences relative to T1 and
no F1, MCC, or final binary-prediction differences.

T4 is reported separately as a three-seed, three-round feasibility study and
is not interpreted as a full-horizon replacement for the B0--T3 experiment.

Protected-Aggregation Fidelity

Protected aggregates are compared against their corresponding plaintext
FedAvg references using:

maximum absolute error; and
root-mean-squared error (RMSE).

Both are evaluated against predefined mechanism-specific fidelity gates.
Relative L2 error is retained only as a diagnostic and is not an acceptance
gate.

Final v14.0 results were:

Scenario	Checks	Max absolute error	Max-abs gate	Max RMSE	RMSE gate	Result
B1 xMK-CKKS	100/100	4.29e-7	2.00e-4	1.39e-7	5.00e-5	PASS
T2 DF+KS	100/100	9.64e-7	2.00e-6	2.06e-7	5.00e-7	PASS
T3 xMK-CKKS	100/100	3.32e-7	2.00e-4	8.68e-8	5.00e-5	PASS
T4 SAMK	9/9	4.24e-6	1.00e-4	1.26e-6	1.00e-4	PASS

T4 additionally passed all 108/108 authorized-recipient aggregate
decryptions:

3 seeds × 3 rounds × 12 authorized recipients = 108

These fidelity tests characterize numerical agreement of the implemented
reference mechanisms with plaintext aggregation. They are not formal
cryptographic-security proofs.

Final v14.0 Operational Results

Communication is reported in decimal KB as generated protocol-object volume.

Scenario	Plaintext/client (KB)	Ciphertext/client (KB)	Protocol communication/round (KB)	Crypto time/round (s)	Runtime/seed (s)
B0 Plain FL	0.240	--	9.60	0.00	19.6
B1 xMK-CKKS	0.240	28.67	1151.68	10.86	240.6
A1 TADP	0.240	--	5.76	0.00	10.8
T1 Plain TADP	0.240	--	5.76	0.00	22.9
T2 DF+KS	0.240	75.00	1007.88	4.21	108.4
T3 xMK-CKKS	0.240	28.67	691.01	6.57	156.6
T4 SAMK	0.240	1609.98	19697.01	1145.78	3574.4

These results demonstrate that cost is mechanism-dependent, not simply
monotonic with tier number.

For example, T3 communicates less per round than T2 because the implemented
xMK-CKKS path packs the model coordinates into one plaintext polynomial,
whereas the DF+KS implementation operates on separate encrypted model
coordinates. T3 nevertheless requires additional collaborative-decryption
computation.

T4 is substantially more resource intensive and is therefore treated as a
reference feasibility implementation rather than a production baseline.

Protocol-Enforcement Results

Three dedicated protocol-enforcement experiments were executed using
three seeds and one round per seed.

Profile	Injected violation	Injected	Blocked	Benign blocked	Effective clients
T1	Invalid signature	2	2/2	0	10
T2	Replay/stale update	1	1/1	0	11
T3	PoFC overflow	3	3/3	0	9

All injected protocol violations were blocked before aggregation, and no
violating update was aggregated.

These experiments demonstrate the implemented:

authentication/signature verification;
freshness and anti-replay controls; and
challenge-bound participation-control enforcement.

They do not establish general robustness against:

semantic data poisoning;
backdoor attacks;
arbitrary Byzantine clients; or
network-level denial-of-service attacks.
T4 Dropout and Delayed Recovery

The dedicated T4 availability experiment uses:

3 seeds × 1 round
2 pre-upload dropouts per run
10 surviving uploaders

Across all three runs:

pre-upload non-uploaders were excluded from the survivor aggregate;
the remaining 10 clients formed the protected aggregate;
the T4 protection profile was not downgraded;
delayed post-upload recipient recovery succeeded in 3/3 tests;
protected-aggregate fidelity passed; and
the server did not recover the plaintext aggregate.

The experiment tests the implemented T4 availability/recovery behavior only
and should not be interpreted as a production service-level availability
guarantee.

Average-Precision Non-Inferiority

The B0--T3 main comparative experiment uses a predefined Average Precision
non-inferiority margin of:

delta = 0.005

The planned comparisons were frozen before the canonical full-dataset run.

For the governance effect specifically, the A1 TADP cohort achieved:

Delta AP vs B0 ≈ -0.0013

and satisfied the predefined AP non-inferiority criterion relative to the
20-client B0 plain-FL reference.

This means the observed AP reduction remained within the predefined
acceptable-loss boundary. It does not mean that governance improved model
accuracy or AP.

T4 is treated separately as a short feasibility experiment rather than being
included in the five-seed B0--T3 inferential comparison.

Governance Robustness Analysis

Post-freeze sensitivity analysis replays the stored v14.0 governance records
without retraining the FL models or retuning the policy.

The baseline replay reproduced all admission decisions:

Baseline admitted = 12/20

Admission remained unchanged under most tested single perturbations.

Selected outcomes include:

T_R and T_A jointly -30% : 12 admitted
T_R and T_A jointly +10% : 6 admitted
T_R and T_A jointly +30% : 3 admitted
DQ weight -30%            : 11 admitted
Remove DQ (LODO)          : 6 admitted
Remove any other dimension: 12 admitted

These results characterize sensitivity of the evaluated controlled cohort
under the frozen v14.0 policy. They do not imply that Data Quality or any
other dimension has the same relative importance in every application.

Audit and Reproducibility

The implementation maintains a tamper-evident audit architecture comprising:

a central governance/runtime ledger;
logical client-specific ledgers;
a cryptographic-events ledger;
hash-chained records;
signed checkpoints;
persisted audit artifacts; and
final subledger seals committed through a root-of-roots record.

The single-process reference experiment stores these artifacts in one output
tree. The client ledgers therefore represent logical client-specific
ledgers, not physically distributed storage.

The ledger files contain audit metadata and cryptographic hashes rather than
raw client datasets or private cryptographic keys.

The final v14.0 run produced 22 final ledger seals.

Main Generated Artifacts

The experiment generates, among other outputs:

all_scenarios_results_comprehensive.csv

stats/
├── TADP_Sec_Publication_Report.html
├── publication_operational_comparison_b0_t4.csv
├── publication_protocol_enforcement_attack_only.csv
├── publication_samk_dropout_robustness.csv
├── publication_aggregate_fidelity_diagnostics.csv
├── noninferiority_ap_planned_contrasts.csv
├── metric_equivalence_diagnostics_summary.csv
├── metric_equivalence_diagnostics_per_seed.csv
├── machine_specification.json
├── crypto_parameter_profile.json
└── governance_robustness/

figs/
├── learning_curves_600dpi.png
├── learning_curves_vector.pdf
├── TADP_Sec_Four_Panel_2x2_600dpi.png
└── TADP_Sec_Four_Panel_2x2_vector.pdf

Additional ledgers, audit artifacts, cryptographic artifacts, manifests, and
diagnostics are included in the complete results archive.

Repository Structure
TADP-Sec/
├── README.md
├── TADP-Sec_Canonical_Experiment/
│   └── Canonical TADP-Sec v14.0 implementation and supporting results
├── TADP-Sec_Supplementary_Material.pdf
├── crypto_artifacts/
├── figs/
├── ledgers/
├── stats/
└── LICENSE
Important Interpretation Notes

TADP-Sec should be interpreted as a governance-to-runtime research
framework, not as evidence that every deployment using the framework is
automatically a fully trustworthy AI system.

The reported experiment demonstrates:

evidence-based governance admission;
critical-dimension safeguards;
deterministic governance-to-runtime policy selection;
implementation-backed T1--T4 profiles;
numerical fidelity of protected aggregation;
protocol-level enforcement;
T4 dropout/delayed-recovery behavior; and
tamper-evident auditability.

The current evaluation remains limited to one dataset and model family,
controlled governance/CIA-BI archetypes, and research/reference cryptographic
implementations.

Production deployment would additionally require real organizational
governance evidence, deployment-specific policy validation, optimized and
audited cryptographic libraries, broader adversarial testing, operational
monitoring, infrastructure security, and application-specific assurance.
