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
