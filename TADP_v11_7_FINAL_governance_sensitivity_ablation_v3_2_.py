# ============================================================
# TADP-SEC v11.7
# COMPLETE GOVERNANCE SENSITIVITY + ABLATION ANALYSIS
#
# RUN ONLY AFTER:
# the final TADP-Sec v11.7 main experiment (v3.2 corrected build)
# HAS FINISHED and written stats/admission_results.json.
# This analysis reads only frozen Stage-1 governance results and is independent of metric-reporting fixes.
#
# This analysis reads ONLY the frozen Stage-1 admission results.
# It does NOT rerun federated learning, cryptography, T1-T4,
# SAMK, or attack experiments.
# ============================================================

from pathlib import Path
import json
import math
import shutil
import hashlib
import warnings

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


# ============================================================
# 0. PATHS
# ============================================================

RESULTS_DIR = Path("/content/tadp_sec_results_v11_7")

ADMISSION_JSON = (
    RESULTS_DIR
    / "stats"
    / "admission_results.json"
)

ANALYSIS_DIR = (
    RESULTS_DIR
    / "stats"
    / "governance_sensitivity_ablation_v11_7"
)

FIG_DIR = ANALYSIS_DIR / "figures"


if not ADMISSION_JSON.exists():
    raise FileNotFoundError(
        f"Missing admission results:\n{ADMISSION_JSON}\n\n"
        "Run the complete v11.7 experiment first."
    )


# Start from a clean analysis directory.
# This prevents old sensitivity outputs from being mixed with
# the current frozen v11.7 results.

if ANALYSIS_DIR.exists():
    shutil.rmtree(ANALYSIS_DIR)

FIG_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# 1. FROZEN v11.7 GOVERNANCE POLICY
# ============================================================

DIMENSIONS = (
    "source_reliability",
    "data_quality",
    "documentation",
    "timeliness",
    "regulatory",
    "context",
)


DISPLAY = {
    "source_reliability": "Source Reliability",
    "data_quality": "Data Quality",
    "documentation": "Documentation",
    "timeliness": "Timeliness",
    "regulatory": "Regulatory",
    "context": "Context",
}


# Exact frozen v11.7 weights.

BASE_WEIGHTS = {
    "source_reliability": 0.20,
    "data_quality": 0.25,
    "documentation": 0.15,
    "timeliness": 0.15,
    "regulatory": 0.15,
    "context": 0.10,
}


# Exact frozen v11.7 critical dimensions.

BASE_CRITICAL = (
    "source_reliability",
    "data_quality",
    "regulatory",
    "context",
)


# Exact frozen v11.7 thresholds.

T_R0 = 3.0
T_A0 = 4.0

T_C_DIRECT0 = 4.0
T_C_REVIEW0 = 3.5

C_MIN0 = 3.0


# ±10%, ±20%, ±30%, with zero baseline included.

PERTURBATIONS = (
    -0.30,
    -0.20,
    -0.10,
     0.00,
     0.10,
     0.20,
     0.30,
)


EPS = 1e-12


# ============================================================
# 2. GENERAL HELPERS
# ============================================================

def sha256_file(path: Path) -> str:
    """
    Compute SHA-256 for provenance.
    """
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b""
        ):
            h.update(chunk)

    return h.hexdigest()


def pct_label(delta: float) -> str:
    """
    Format relative perturbation.
    """
    if abs(delta) < 1e-15:
        return "0%"

    return f"{delta * 100:+.0f}%"


def clip_score_threshold(
    x: float
):
    """
    HPS lives on a 0..5 scale.

    Threshold perturbations that exceed that scale are clipped,
    but this is explicitly recorded in the result table.
    """

    original = float(x)

    clipped = min(
        5.0,
        max(
            0.0,
            original
        )
    )

    was_clipped = not math.isclose(
        clipped,
        original,
        abs_tol=1e-12
    )

    return clipped, was_clipped


def normalize_weights(
    weights: dict
) -> dict:
    """
    Normalize supplied weights so that they sum exactly to one.
    """

    total = float(
        sum(weights.values())
    )

    if total <= 0:
        raise ValueError(
            "Weight sum must be positive."
        )

    normalized = {
        k: float(v) / total
        for k, v in weights.items()
    }

    if not math.isclose(
        sum(normalized.values()),
        1.0,
        rel_tol=0,
        abs_tol=1e-12
    ):
        raise RuntimeError(
            "Normalized weights do not sum to 1."
        )

    return normalized


# ============================================================
# 3. WEIGHT PERTURBATION
# ============================================================

def perturb_one_weight(
    base_weights: dict,
    target_dim: str,
    delta: float
) -> dict:
    """
    Perturb ONE dimension weight by a relative percentage.

    The remaining five dimensions are proportionally rescaled,
    preserving their relative proportions while keeping:

        sum(weights) = 1

    Example:
        DQ = 0.25
        +20% -> 0.30

    The remaining 0.70 is distributed proportionally across
    the other dimensions.
    """

    if target_dim not in base_weights:
        raise KeyError(
            target_dim
        )

    old_target = float(
        base_weights[target_dim]
    )

    new_target = (
        old_target
        * (1.0 + float(delta))
    )

    if not (
        0.0
        < new_target
        < 1.0
    ):
        raise ValueError(
            f"Perturbation makes {target_dim} "
            f"weight invalid: {new_target}"
        )

    old_other_total = (
        1.0
        - old_target
    )

    new_other_total = (
        1.0
        - new_target
    )

    scale = (
        new_other_total
        / old_other_total
    )

    new_weights = {}

    for d, w in base_weights.items():

        if d == target_dim:
            new_weights[d] = new_target

        else:
            new_weights[d] = (
                float(w)
                * scale
            )

    return normalize_weights(
        new_weights
    )


# ============================================================
# 4. LEAVE-ONE-DIMENSION-OUT WEIGHTS
# ============================================================

def lodo_weights(
    base_weights: dict,
    omitted_dim: str
) -> dict:
    """
    Remove one dimension completely and renormalize
    the remaining weights.
    """

    kept = {
        d: float(w)
        for d, w in base_weights.items()
        if d != omitted_dim
    }

    return normalize_weights(
        kept
    )


# ============================================================
# 5. EXACT v11.7 ADMISSION MATHEMATICS
# ============================================================

def evaluate_policy(
    dimension_scores: dict,
    weights: dict,
    t_r: float,
    t_a: float,
    critical_dims: tuple,
    c_min: float = C_MIN0,
    t_c_direct: float | None = None,
    t_c_review: float | None = None,
) -> dict:

    """
    Reproduce the frozen v11.7 admission policy.

    Decision order:

    1. HPS < T_R
           -> AUTO_REJECT

    2. Critical minimum < C_min
           -> REMEDIATE

    3. HPS >= T_A
           -> direct accept only when
              HPS_C >= T_C_direct

    4. T_R <= HPS < T_A
           -> automated review
           -> accept when
              HPS_C >= T_C_review

    This ordering intentionally reproduces the main v11.7 code.
    """

    t_r = float(t_r)
    t_a = float(t_a)


    # -----------------------------------------
    # Check threshold validity
    # -----------------------------------------

    if not (
        0.0 <= t_r <= 5.0
        and
        0.0 <= t_a <= 5.0
    ):
        raise ValueError(
            "Thresholds must remain on the 0..5 HPS scale."
        )


    if not (
        t_r < t_a
    ):
        raise ValueError(
            f"Invalid threshold ordering: "
            f"T_R={t_r} must be < T_A={t_a}."
        )


    if t_c_direct is None:
        t_c_direct = t_a


    if t_c_review is None:
        t_c_review = (
            t_r
            + t_a
        ) / 2.0


    t_c_direct = float(
        t_c_direct
    )

    t_c_review = float(
        t_c_review
    )


    # -----------------------------------------
    # Overall HPS
    # -----------------------------------------

    active_dims = tuple(
        weights.keys()
    )


    missing = [
        d
        for d in active_dims
        if d not in dimension_scores
    ]


    if missing:
        raise KeyError(
            f"Missing dimension scores: "
            f"{missing}"
        )


    hps = float(
        sum(
            float(weights[d])
            * float(dimension_scores[d])

            for d
            in active_dims
        )
    )


    # -----------------------------------------
    # Critical HPS
    # -----------------------------------------

    critical_dims = tuple(
        d
        for d in critical_dims
        if d in weights
    )


    if not critical_dims:
        raise ValueError(
            "At least one critical dimension must remain."
        )


    critical_weight_sum = float(
        sum(
            float(weights[d])

            for d
            in critical_dims
        )
    )


    if critical_weight_sum <= 0:
        raise ValueError(
            "Critical weight sum must be positive."
        )


    critical_hps = float(

        sum(
            float(weights[d])
            * float(dimension_scores[d])

            for d
            in critical_dims
        )

        / critical_weight_sum
    )


    critical_min = float(
        min(
            float(dimension_scores[d])

            for d
            in critical_dims
        )
    )


    # ========================================================
    # POLICY DECISION
    # ========================================================

    # 1. Below overall ADEQUATE boundary.

    if hps < t_r - EPS:

        decision = "AUTO_REJECT"
        admitted = False


    # 2. Global critical-dimension minimum.

    elif critical_min < c_min - EPS:

        decision = "REMEDIATE"
        admitted = False


    # 3. Strong overall region.

    elif hps >= t_a - EPS:

        if (
            critical_hps
            >= t_c_direct - EPS
        ):

            decision = "DIRECT_AUTO_ACCEPT"
            admitted = True

        else:

            decision = "REMEDIATE"
            admitted = False


    # 4. Intermediate review region.

    else:

        if (
            critical_hps
            >= t_c_review - EPS
        ):

            decision = (
                "ACCEPT_AFTER_AUTOMATED_REVIEW"
            )

            admitted = True

        else:

            decision = "REMEDIATE"
            admitted = False


    return {

        "hps":
            hps,

        "critical_hps":
            critical_hps,

        "critical_min":
            critical_min,

        "decision":
            decision,

        "admitted":
            bool(admitted),

        "t_r":
            t_r,

        "t_a":
            t_a,

        "t_c_direct":
            t_c_direct,

        "t_c_review":
            t_c_review,

        "c_min":
            float(c_min),
    }


# ============================================================
# 6. THRESHOLD PERTURBATION DEFINITIONS
# ============================================================

def scenario_thresholds(
    mode: str,
    delta: float
) -> dict:

    """
    Three threshold analyses are performed.

    lower_only:
        vary T_R
        keep T_A = 4.0

    upper_only:
        vary T_A
        keep T_R = 3.0

    joint:
        vary T_R and T_A by the same percentage

    IMPORTANT:

        T_C_direct = T_A

        T_C_review =
            (T_R + T_A) / 2

        C_min = 3.0

    Therefore the internal semantics of the final policy
    are preserved during threshold perturbation.
    """


    if mode == "lower_only":

        raw_tr = (
            T_R0
            * (1.0 + delta)
        )

        raw_ta = T_A0


    elif mode == "upper_only":

        raw_tr = T_R0

        raw_ta = (
            T_A0
            * (1.0 + delta)
        )


    elif mode == "joint":

        raw_tr = (
            T_R0
            * (1.0 + delta)
        )

        raw_ta = (
            T_A0
            * (1.0 + delta)
        )


    else:

        raise ValueError(
            f"Unknown threshold mode: {mode}"
        )


    tr, tr_clipped = (
        clip_score_threshold(
            raw_tr
        )
    )


    ta, ta_clipped = (
        clip_score_threshold(
            raw_ta
        )
    )


    # If the lower threshold crosses the upper threshold,
    # this is not a coherent TADP policy.
    #
    # We report the scenario as INVALID rather than silently
    # changing the policy.

    valid = (
        tr
        < ta - EPS
    )


    return {

        "mode":
            mode,

        "delta":
            float(delta),

        "requested_t_r":
            float(raw_tr),

        "requested_t_a":
            float(raw_ta),

        "t_r":
            float(tr),

        "t_a":
            float(ta),

        "t_c_direct":
            float(ta),

        "t_c_review":
            (
                float(
                    (tr + ta)
                    / 2.0
                )
                if valid
                else np.nan
            ),

        "c_min":
            C_MIN0,

        "t_r_clipped":
            bool(tr_clipped),

        "t_a_clipped":
            bool(ta_clipped),

        "valid_policy":
            bool(valid),
    }


# ============================================================
# 7. FIGURE SAVING
# ============================================================

def save_figure(
    fig,
    stem: str
):

    png = (
        FIG_DIR
        / f"{stem}.png"
    )

    pdf = (
        FIG_DIR
        / f"{stem}.pdf"
    )


    fig.savefig(
        png,
        dpi=600,
        bbox_inches="tight"
    )


    fig.savefig(
        pdf,
        bbox_inches="tight"
    )


    plt.close(
        fig
    )


# ============================================================
# 8. LOAD FINAL v11.7 ADMISSION RESULTS
# ============================================================

with ADMISSION_JSON.open(
    "r",
    encoding="utf-8"
) as f:

    raw = json.load(
        f
    )


if isinstance(
    raw,
    list
):

    records = {
        str(r["client_id"]):
            r
        for r
        in raw
    }


elif isinstance(
    raw,
    dict
):

    records = {
        str(k):
            v
        for k, v
        in raw.items()
    }


else:

    raise TypeError(
        "admission_results.json must contain "
        "a dict or list."
    )


if not records:

    raise RuntimeError(
        "No client admission records found."
    )


client_ids = sorted(
    records.keys()
)


dimension_scores_by_client = {}

saved_admitted = {}

saved_decision = {}


for cid in client_ids:

    rec = records[cid]


    dims = rec.get(
        "dimension_scores"
    )


    if not isinstance(
        dims,
        dict
    ):

        raise KeyError(
            f"{cid}: missing dimension_scores."
        )


    missing_dims = [
        d
        for d
        in DIMENSIONS
        if d not in dims
    ]


    if missing_dims:

        raise KeyError(
            f"{cid}: missing dimensions "
            f"{missing_dims}"
        )


    dimension_scores_by_client[cid] = {

        d:
            float(dims[d])

        for d
        in DIMENSIONS
    }


    saved_admitted[cid] = bool(
        rec.get(
            "admitted",
            False
        )
    )


    saved_decision[cid] = str(

        rec.get(

            "review_recommendation",

            rec.get(

                "decision",

                rec.get(
                    "final_action",
                    ""
                )
            )
        )
    )


# ============================================================
# 9. REPLAY THE FROZEN BASELINE
# ============================================================

baseline_eval = {

    cid:

        evaluate_policy(

            dimension_scores_by_client[cid],

            BASE_WEIGHTS,

            T_R0,

            T_A0,

            BASE_CRITICAL,

            C_MIN0,

            T_C_DIRECT0,

            T_C_REVIEW0,
        )

    for cid
    in client_ids
}


baseline_admitted = {

    cid:
        bool(x["admitted"])

    for cid, x
    in baseline_eval.items()
}


baseline_decision = {

    cid:
        str(x["decision"])

    for cid, x
    in baseline_eval.items()
}


# ============================================================
# 10. VERIFY ANALYSIS REPRODUCES FINAL v11.7
# ============================================================

mismatches = [

    cid

    for cid
    in client_ids

    if (
        baseline_admitted[cid]
        != saved_admitted[cid]
    )
]


if mismatches:

    raise RuntimeError(

        "Baseline replay does not match the saved "
        "v11.7 admission decisions for:\n"

        + ", ".join(
            mismatches
        )
    )


BASE_N = len(
    client_ids
)


BASE_ADMITTED = sum(
    baseline_admitted.values()
)


BASE_NOT_ADMITTED = (
    BASE_N
    - BASE_ADMITTED
)


BASE_SET = {

    cid

    for cid, value
    in baseline_admitted.items()

    if value
}


print(
    "=" * 88
)

print(
    "TADP v11.7 GOVERNANCE ROBUSTNESS ANALYSIS"
)

print(
    "=" * 88
)

print(
    f"Clients: {BASE_N}"
)

print(
    f"Baseline admitted: {BASE_ADMITTED}"
)

print(
    f"Baseline not admitted: {BASE_NOT_ADMITTED}"
)

print(

    f"Frozen thresholds: "

    f"T_R={T_R0:.2f}, "

    f"T_A={T_A0:.2f}, "

    f"T_C_direct={T_C_DIRECT0:.2f}, "

    f"T_C_review={T_C_REVIEW0:.2f}, "

    f"C_min={C_MIN0:.2f}"
)

print(
    "Baseline replay vs saved admission_results.json: PASSED"
)


# ============================================================
# 11. SAVE BASELINE CLIENT TABLE
# ============================================================

baseline_rows = []


for cid in client_ids:

    e = baseline_eval[cid]


    row = {

        "Client":
            cid,

        "Saved admitted":
            saved_admitted[cid],

        "Baseline admitted":
            e["admitted"],

        "Baseline decision":
            e["decision"],

        "HPS":
            e["hps"],

        "Critical HPS":
            e["critical_hps"],

        "Critical minimum":
            e["critical_min"],
    }


    row.update({

        DISPLAY[d]:
            dimension_scores_by_client[cid][d]

        for d
        in DIMENSIONS
    })


    baseline_rows.append(
        row
    )


baseline_df = pd.DataFrame(
    baseline_rows
)


baseline_df.to_csv(

    ANALYSIS_DIR
    / "00_baseline_replay.csv",

    index=False
)


# ============================================================
# 12. BASELINE COMPARISON METRICS
# ============================================================

def compare_to_baseline(
    eval_map: dict
) -> dict:

    status = {

        cid:
            bool(eval_map[cid]["admitted"])

        for cid
        in client_ids
    }


    decisions = {

        cid:
            str(eval_map[cid]["decision"])

        for cid
        in client_ids
    }


    admitted_set = {

        cid

        for cid, value
        in status.items()

        if value
    }


    n_admitted = len(
        admitted_set
    )


    admission_flips = sum(

        status[cid]
        != baseline_admitted[cid]

        for cid
        in client_ids
    )


    decision_category_flips = sum(

        decisions[cid]
        != baseline_decision[cid]

        for cid
        in client_ids
    )


    lost = sorted(
        BASE_SET
        - admitted_set
    )


    gained = sorted(
        admitted_set
        - BASE_SET
    )


    union = (
        BASE_SET
        | admitted_set
    )


    if not union:

        jaccard = 1.0

    else:

        jaccard = (

            len(
                BASE_SET
                & admitted_set
            )

            / len(
                union
            )
        )


    return {

        "Admitted":
            n_admitted,

        "Delta admitted":
            (
                n_admitted
                - BASE_ADMITTED
            ),

        "Not admitted":
            (
                BASE_N
                - n_admitted
            ),

        "Delta not admitted":
            (
                (
                    BASE_N
                    - n_admitted
                )
                - BASE_NOT_ADMITTED
            ),

        "Admission flips":
            admission_flips,

        "Admission flip rate":
            (
                admission_flips
                / BASE_N
            ),

        "Decision-category flips":
            decision_category_flips,

        "Lost admissions":
            len(lost),

        "New admissions":
            len(gained),

        "Lost client IDs":
            "|".join(lost),

        "New client IDs":
            "|".join(gained),

        "Admitted-set Jaccard":
            jaccard,

        "Direct auto-accept":
            sum(
                e["decision"]
                == "DIRECT_AUTO_ACCEPT"

                for e
                in eval_map.values()
            ),

        "Review accept":
            sum(
                e["decision"]
                == "ACCEPT_AFTER_AUTOMATED_REVIEW"

                for e
                in eval_map.values()
            ),

        "Remediate":
            sum(
                e["decision"]
                == "REMEDIATE"

                for e
                in eval_map.values()
            ),

        "Auto-reject":
            sum(
                e["decision"]
                == "AUTO_REJECT"

                for e
                in eval_map.values()
            ),
    }


# ============================================================
# 13. CLIENT-LEVEL DETAILS
# ============================================================

def client_detail_rows(
    eval_map: dict,
    scenario_meta: dict
):

    rows = []


    for cid in client_ids:

        e = eval_map[cid]

        b = baseline_eval[cid]


        rows.append({

            **scenario_meta,

            "Client":
                cid,

            "Baseline admitted":
                baseline_admitted[cid],

            "Scenario admitted":
                e["admitted"],

            "Admission status changed":
                (
                    e["admitted"]
                    != baseline_admitted[cid]
                ),

            "Baseline decision":
                b["decision"],

            "Scenario decision":
                e["decision"],

            "Decision category changed":
                (
                    e["decision"]
                    != b["decision"]
                ),

            "Baseline HPS":
                b["hps"],

            "Scenario HPS":
                e["hps"],

            "Delta HPS":
                (
                    e["hps"]
                    - b["hps"]
                ),

            "Baseline critical HPS":
                b["critical_hps"],

            "Scenario critical HPS":
                e["critical_hps"],

            "Delta critical HPS":
                (
                    e["critical_hps"]
                    - b["critical_hps"]
                ),

            "Baseline critical minimum":
                b["critical_min"],

            "Scenario critical minimum":
                e["critical_min"],
        })


    return rows


# ============================================================
# 14. ANALYSIS 1 — THRESHOLD SENSITIVITY
# ============================================================

threshold_summary_rows = []

threshold_detail_rows = []


for mode in (

    "lower_only",

    "upper_only",

    "joint",
):


    for delta in PERTURBATIONS:


        th = scenario_thresholds(
            mode,
            delta
        )


        meta = {

            "Threshold mode":
                mode,

            "Threshold perturbation":
                pct_label(delta),

            "Threshold delta":
                delta,

            "Requested T_R":
                th["requested_t_r"],

            "Requested T_A":
                th["requested_t_a"],

            "Applied T_R":
                th["t_r"],

            "Applied T_A":
                th["t_a"],

            "T_C_direct":
                th["t_c_direct"],

            "T_C_review":
                th["t_c_review"],

            "C_min":
                th["c_min"],

            "T_R clipped":
                th["t_r_clipped"],

            "T_A clipped":
                th["t_a_clipped"],

            "Valid policy":
                th["valid_policy"],
        }


        # -----------------------------------------
        # Invalid threshold combination
        # -----------------------------------------

        if not th["valid_policy"]:

            threshold_summary_rows.append({

                **meta,

                "Admitted":
                    np.nan,

                "Delta admitted":
                    np.nan,

                "Not admitted":
                    np.nan,

                "Delta not admitted":
                    np.nan,

                "Admission flips":
                    np.nan,

                "Admission flip rate":
                    np.nan,

                "Decision-category flips":
                    np.nan,

                "Lost admissions":
                    np.nan,

                "New admissions":
                    np.nan,

                "Lost client IDs":
                    "",

                "New client IDs":
                    "",

                "Admitted-set Jaccard":
                    np.nan,

                "Direct auto-accept":
                    np.nan,

                "Review accept":
                    np.nan,

                "Remediate":
                    np.nan,

                "Auto-reject":
                    np.nan,
            })


            continue


        # -----------------------------------------
        # Evaluate all clients
        # -----------------------------------------

        eval_map = {

            cid:

                evaluate_policy(

                    dimension_scores_by_client[cid],

                    BASE_WEIGHTS,

                    th["t_r"],

                    th["t_a"],

                    BASE_CRITICAL,

                    C_MIN0,

                    th["t_c_direct"],

                    th["t_c_review"],
                )

            for cid
            in client_ids
        }


        metrics = compare_to_baseline(
            eval_map
        )


        threshold_summary_rows.append({

            **meta,

            **metrics
        })


        threshold_detail_rows.extend(

            client_detail_rows(
                eval_map,
                meta
            )
        )


threshold_summary_df = pd.DataFrame(
    threshold_summary_rows
)


threshold_detail_df = pd.DataFrame(
    threshold_detail_rows
)


threshold_summary_df.to_csv(

    ANALYSIS_DIR
    / "01_threshold_sensitivity_summary.csv",

    index=False
)


threshold_detail_df.to_csv(

    ANALYSIS_DIR
    / "02_threshold_sensitivity_client_details.csv",

    index=False
)


# ============================================================
# 15. THRESHOLD SENSITIVITY FIGURES
# ============================================================

for mode in (

    "lower_only",

    "upper_only",

    "joint",
):


    sub = threshold_summary_df[

        (
            threshold_summary_df[
                "Threshold mode"
            ]
            == mode
        )

        &

        (
            threshold_summary_df[
                "Valid policy"
            ]
            == True
        )

    ].copy()


    sub = sub.sort_values(
        "Threshold delta"
    )


    fig, ax = plt.subplots(
        figsize=(7.2, 4.8)
    )


    ax.plot(

        sub["Threshold delta"]
        * 100.0,

        sub["Delta admitted"],

        marker="o"
    )


    ax.axhline(
        0.0,
        linewidth=1.0
    )


    ax.set_xlabel(
        "Threshold perturbation (%)"
    )


    ax.set_ylabel(
        "Δ admitted clients vs baseline"
    )


    ax.set_title(

        "Threshold sensitivity — "

        + mode.replace(
            "_",
            " "
        )
    )


    ax.grid(
        True,
        alpha=0.25
    )


    save_figure(

        fig,

        f"threshold_{mode}_delta_admitted"
    )


# ============================================================
# 16. ANALYSIS 2 — WEIGHT SENSITIVITY
# ============================================================

weight_summary_rows = []

weight_detail_rows = []


for dim in DIMENSIONS:


    for delta in PERTURBATIONS:


        if abs(delta) < EPS:

            w = BASE_WEIGHTS.copy()


        else:

            w = perturb_one_weight(

                BASE_WEIGHTS,

                dim,

                delta
            )


        # Recompute BOTH:
        #
        # HPS
        # HPS_C
        #
        # because critical weights may also have changed.

        eval_map = {

            cid:

                evaluate_policy(

                    dimension_scores_by_client[cid],

                    w,

                    T_R0,

                    T_A0,

                    BASE_CRITICAL,

                    C_MIN0,

                    T_C_DIRECT0,

                    T_C_REVIEW0,
                )

            for cid
            in client_ids
        }


        meta = {

            "Perturbed dimension":
                dim,

            "Perturbed dimension display":
                DISPLAY[dim],

            "Weight perturbation":
                pct_label(delta),

            "Weight delta":
                delta,

            "Baseline target weight":
                BASE_WEIGHTS[dim],

            "New target weight":
                w[dim],
        }


        # Save all resulting weights for reproducibility.

        for d in DIMENSIONS:

            meta[
                f"Weight::{d}"
            ] = w[d]


        metrics = compare_to_baseline(
            eval_map
        )


        weight_summary_rows.append({

            **meta,

            **metrics
        })


        weight_detail_rows.extend(

            client_detail_rows(
                eval_map,
                meta
            )
        )


weight_summary_df = pd.DataFrame(
    weight_summary_rows
)


weight_detail_df = pd.DataFrame(
    weight_detail_rows
)


weight_summary_df.to_csv(

    ANALYSIS_DIR
    / "03_weight_sensitivity_summary.csv",

    index=False
)


weight_detail_df.to_csv(

    ANALYSIS_DIR
    / "04_weight_sensitivity_client_details.csv",

    index=False
)


# ============================================================
# 17. WEIGHT SENSITIVITY HEATMAP — Δ ADMITTED
# ============================================================

weight_pivot = (

    weight_summary_df

    .pivot(

        index=
            "Perturbed dimension display",

        columns=
            "Weight delta",

        values=
            "Delta admitted"
    )

    .reindex(
        [
            DISPLAY[d]
            for d
            in DIMENSIONS
        ]
    )
)


fig, ax = plt.subplots(
    figsize=(9.2, 5.2)
)


im = ax.imshow(
    weight_pivot.values,
    aspect="auto"
)


ax.set_xticks(
    range(
        len(
            weight_pivot.columns
        )
    )
)


ax.set_xticklabels(

    [
        pct_label(
            float(x)
        )

        for x
        in weight_pivot.columns
    ]
)


ax.set_yticks(
    range(
        len(
            weight_pivot.index
        )
    )
)


ax.set_yticklabels(
    weight_pivot.index
)


ax.set_xlabel(
    "Relative weight perturbation"
)


ax.set_ylabel(
    "Dimension"
)


ax.set_title(
    "Weight sensitivity — Δ admitted clients"
)


for i in range(
    weight_pivot.shape[0]
):

    for j in range(
        weight_pivot.shape[1]
    ):

        v = weight_pivot.iloc[
            i,
            j
        ]


        ax.text(

            j,
            i,

            f"{int(v):+d}",

            ha="center",
            va="center"
        )


fig.colorbar(
    im,
    ax=ax,
    label="Δ admitted"
)


save_figure(

    fig,

    "weight_sensitivity_delta_admitted_heatmap"
)


# ============================================================
# 18. WEIGHT SENSITIVITY HEATMAP — ADMISSION FLIPS
# ============================================================

flip_pivot = (

    weight_summary_df

    .pivot(

        index=
            "Perturbed dimension display",

        columns=
            "Weight delta",

        values=
            "Admission flips"
    )

    .reindex(
        [
            DISPLAY[d]
            for d
            in DIMENSIONS
        ]
    )
)


fig, ax = plt.subplots(
    figsize=(9.2, 5.2)
)


im = ax.imshow(
    flip_pivot.values,
    aspect="auto"
)


ax.set_xticks(
    range(
        len(
            flip_pivot.columns
        )
    )
)


ax.set_xticklabels(

    [
        pct_label(
            float(x)
        )

        for x
        in flip_pivot.columns
    ]
)


ax.set_yticks(
    range(
        len(
            flip_pivot.index
        )
    )
)


ax.set_yticklabels(
    flip_pivot.index
)


ax.set_xlabel(
    "Relative weight perturbation"
)


ax.set_ylabel(
    "Dimension"
)


ax.set_title(
    "Weight sensitivity — admission-status flips"
)


for i in range(
    flip_pivot.shape[0]
):

    for j in range(
        flip_pivot.shape[1]
    ):

        v = flip_pivot.iloc[
            i,
            j
        ]


        ax.text(

            j,
            i,

            f"{int(v)}",

            ha="center",
            va="center"
        )


fig.colorbar(

    im,

    ax=ax,

    label=
        "Number of admission flips"
)


save_figure(

    fig,

    "weight_sensitivity_admission_flips_heatmap"
)


# ============================================================
# 19. ANALYSIS 3 — JOINT THRESHOLD × WEIGHT SENSITIVITY
# ============================================================

# Threshold side:
#
# T_R and T_A are perturbed together.
#
# T_C_direct follows T_A.
#
# T_C_review remains:
#
#       (T_R + T_A) / 2
#
#
# Weight side:
#
# one dimension at a time is perturbed
# ±10%, ±20%, ±30%.
#
#
# Each dimension therefore receives its own
# 7 × 7 interaction heatmap.


joint_summary_rows = []

joint_detail_rows = []


for dim in DIMENSIONS:


    for threshold_delta in PERTURBATIONS:


        th = scenario_thresholds(

            "joint",

            threshold_delta
        )


        if not th["valid_policy"]:

            continue


        for weight_delta in PERTURBATIONS:


            if abs(
                weight_delta
            ) < EPS:

                w = (
                    BASE_WEIGHTS.copy()
                )


            else:

                w = perturb_one_weight(

                    BASE_WEIGHTS,

                    dim,

                    weight_delta
                )


            eval_map = {

                cid:

                    evaluate_policy(

                        dimension_scores_by_client[cid],

                        w,

                        th["t_r"],

                        th["t_a"],

                        BASE_CRITICAL,

                        C_MIN0,

                        th["t_c_direct"],

                        th["t_c_review"],
                    )

                for cid
                in client_ids
            }


            meta = {

                "Perturbed dimension":
                    dim,

                "Perturbed dimension display":
                    DISPLAY[dim],

                "Threshold perturbation":
                    pct_label(
                        threshold_delta
                    ),

                "Threshold delta":
                    threshold_delta,

                "Weight perturbation":
                    pct_label(
                        weight_delta
                    ),

                "Weight delta":
                    weight_delta,

                "Applied T_R":
                    th["t_r"],

                "Applied T_A":
                    th["t_a"],

                "T_C_direct":
                    th["t_c_direct"],

                "T_C_review":
                    th["t_c_review"],

                "T_R clipped":
                    th["t_r_clipped"],

                "T_A clipped":
                    th["t_a_clipped"],

                "New target weight":
                    w[dim],
            }


            metrics = compare_to_baseline(
                eval_map
            )


            joint_summary_rows.append({

                **meta,

                **metrics
            })


            joint_detail_rows.extend(

                client_detail_rows(
                    eval_map,
                    meta
                )
            )


joint_summary_df = pd.DataFrame(
    joint_summary_rows
)


joint_detail_df = pd.DataFrame(
    joint_detail_rows
)


joint_summary_df.to_csv(

    ANALYSIS_DIR
    / "05_joint_threshold_weight_sensitivity_summary.csv",

    index=False
)


joint_detail_df.to_csv(

    ANALYSIS_DIR
    / "06_joint_threshold_weight_sensitivity_client_details.csv",

    index=False
)


# ============================================================
# 20. JOINT SENSITIVITY HEATMAPS
# ============================================================

for dim in DIMENSIONS:


    sub = joint_summary_df[

        joint_summary_df[
            "Perturbed dimension"
        ]
        == dim

    ].copy()


    pivot = (

        sub

        .pivot(

            index=
                "Weight delta",

            columns=
                "Threshold delta",

            values=
                "Delta admitted"
        )

        .sort_index(
            ascending=True
        )
    )


    fig, ax = plt.subplots(
        figsize=(8.0, 6.0)
    )


    im = ax.imshow(
        pivot.values,
        aspect="auto"
    )


    ax.set_xticks(
        range(
            len(
                pivot.columns
            )
        )
    )


    ax.set_xticklabels(

        [
            pct_label(
                float(x)
            )

            for x
            in pivot.columns
        ]
    )


    ax.set_yticks(
        range(
            len(
                pivot.index
            )
        )
    )


    ax.set_yticklabels(

        [
            pct_label(
                float(x)
            )

            for x
            in pivot.index
        ]
    )


    ax.set_xlabel(
        "Joint threshold perturbation "
        "(T_R and T_A)"
    )


    ax.set_ylabel(

        f"{DISPLAY[dim]} "
        "weight perturbation"
    )


    ax.set_title(

        "Joint sensitivity — "
        f"{DISPLAY[dim]} — Δ admitted"
    )


    for i in range(
        pivot.shape[0]
    ):

        for j in range(
            pivot.shape[1]
        ):

            v = pivot.iloc[
                i,
                j
            ]


            ax.text(

                j,
                i,

                f"{int(v):+d}",

                ha="center",
                va="center"
            )


    fig.colorbar(

        im,

        ax=ax,

        label="Δ admitted"
    )


    save_figure(

        fig,

        f"joint_{dim}_delta_admitted_heatmap"
    )


# ============================================================
# 21. JOINT SENSITIVITY DIMENSION SUMMARY
# ============================================================

joint_dim_summary = []


for dim in DIMENSIONS:


    sub = joint_summary_df[

        joint_summary_df[
            "Perturbed dimension"
        ]
        == dim

    ].copy()


    idx_delta = (

        sub[
            "Delta admitted"
        ]

        .abs()

        .idxmax()
    )


    idx_flips = (

        sub[
            "Admission flips"
        ]

        .idxmax()
    )


    row_delta = sub.loc[
        idx_delta
    ]


    row_flips = sub.loc[
        idx_flips
    ]


    joint_dim_summary.append({

        "Dimension":
            dim,

        "Dimension display":
            DISPLAY[dim],

        "Max absolute Δ admitted":
            abs(
                float(
                    row_delta[
                        "Delta admitted"
                    ]
                )
            ),

        "At threshold perturbation for max |Δ admitted|":
            row_delta[
                "Threshold perturbation"
            ],

        "At weight perturbation for max |Δ admitted|":
            row_delta[
                "Weight perturbation"
            ],

        "Signed Δ admitted at that point":
            float(
                row_delta[
                    "Delta admitted"
                ]
            ),

        "Maximum admission flips":
            int(
                row_flips[
                    "Admission flips"
                ]
            ),

        "At threshold perturbation for max flips":
            row_flips[
                "Threshold perturbation"
            ],

        "At weight perturbation for max flips":
            row_flips[
                "Weight perturbation"
            ],
    })


joint_dim_summary_df = (

    pd.DataFrame(
        joint_dim_summary
    )

    .sort_values(

        [
            "Maximum admission flips",
            "Max absolute Δ admitted"
        ],

        ascending=False
    )
)


joint_dim_summary_df.to_csv(

    ANALYSIS_DIR
    / "07_joint_sensitivity_dimension_summary.csv",

    index=False
)


# ============================================================
# 22. ANALYSIS 4 — LEAVE-ONE-DIMENSION-OUT ABLATION
# ============================================================

ablation_summary_rows = []

ablation_detail_rows = []


for omitted in DIMENSIONS:


    # Remove dimension from overall HPS weights.

    w = lodo_weights(

        BASE_WEIGHTS,

        omitted
    )


    # If the omitted dimension was critical,
    # remove it from the critical set too.
    #
    # This measures the FULL policy contribution of that
    # dimension, not merely its additive HPS contribution.

    critical_after = tuple(

        d

        for d
        in BASE_CRITICAL

        if d != omitted
    )


    eval_map = {

        cid:

            evaluate_policy(

                dimension_scores_by_client[cid],

                w,

                T_R0,

                T_A0,

                critical_after,

                C_MIN0,

                T_C_DIRECT0,

                T_C_REVIEW0,
            )

        for cid
        in client_ids
    }


    metrics = compare_to_baseline(
        eval_map
    )


    delta_hps_values = np.array(

        [

            eval_map[cid]["hps"]
            -
            baseline_eval[cid]["hps"]

            for cid
            in client_ids
        ],

        dtype=float
    )


    delta_critical_values = np.array(

        [

            eval_map[cid]["critical_hps"]
            -
            baseline_eval[cid]["critical_hps"]

            for cid
            in client_ids
        ],

        dtype=float
    )


    summary = {

        "Omitted dimension":
            omitted,

        "Omitted dimension display":
            DISPLAY[omitted],

        "Was critical dimension":
            (
                omitted
                in BASE_CRITICAL
            ),

        "Critical set after ablation":
            "|".join(
                critical_after
            ),

        "Omitted baseline weight":
            BASE_WEIGHTS[omitted],

        **metrics,

        "Mean ΔHPS":
            float(
                delta_hps_values.mean()
            ),

        "Mean |ΔHPS|":
            float(
                np.abs(
                    delta_hps_values
                ).mean()
            ),

        "Median |ΔHPS|":
            float(
                np.median(
                    np.abs(
                        delta_hps_values
                    )
                )
            ),

        "Max |ΔHPS|":
            float(
                np.abs(
                    delta_hps_values
                ).max()
            ),

        "Mean Δ critical HPS":
            float(
                delta_critical_values.mean()
            ),

        "Mean |Δ critical HPS|":
            float(
                np.abs(
                    delta_critical_values
                ).mean()
            ),
    }


    ablation_summary_rows.append(
        summary
    )


    # -----------------------------------------
    # Client-level ablation details
    # -----------------------------------------

    for cid in client_ids:


        e = eval_map[cid]

        b = baseline_eval[cid]


        ablation_detail_rows.append({

            "Omitted dimension":
                omitted,

            "Omitted dimension display":
                DISPLAY[omitted],

            "Was critical dimension":
                (
                    omitted
                    in BASE_CRITICAL
                ),

            "Client":
                cid,

            "Baseline admitted":
                b["admitted"],

            "Ablated admitted":
                e["admitted"],

            "Admission status changed":
                (
                    b["admitted"]
                    != e["admitted"]
                ),

            "Baseline decision":
                b["decision"],

            "Ablated decision":
                e["decision"],

            "Decision category changed":
                (
                    b["decision"]
                    != e["decision"]
                ),

            "Baseline HPS":
                b["hps"],

            "Ablated HPS":
                e["hps"],

            "Delta HPS":
                (
                    e["hps"]
                    - b["hps"]
                ),

            "Baseline critical HPS":
                b["critical_hps"],

            "Ablated critical HPS":
                e["critical_hps"],

            "Delta critical HPS":
                (
                    e["critical_hps"]
                    - b["critical_hps"]
                ),

            "Baseline critical minimum":
                b["critical_min"],

            "Ablated critical minimum":
                e["critical_min"],
        })


ablation_summary_df = (

    pd.DataFrame(
        ablation_summary_rows
    )

    .sort_values(

        [
            "Admission flips",
            "Mean |ΔHPS|"
        ],

        ascending=False
    )
)


ablation_detail_df = pd.DataFrame(
    ablation_detail_rows
)


ablation_summary_df.to_csv(

    ANALYSIS_DIR
    / "08_ablation_lodo_summary.csv",

    index=False
)


ablation_detail_df.to_csv(

    ANALYSIS_DIR
    / "09_ablation_lodo_client_details.csv",

    index=False
)


# ============================================================
# 23. ABLATION FIGURE — ADMISSION FLIPS
# ============================================================

plot_df = (

    ablation_summary_df

    .sort_values(
        "Admission flips",
        ascending=False
    )
)


fig, ax = plt.subplots(
    figsize=(8.2, 4.8)
)


ax.bar(

    plot_df[
        "Omitted dimension display"
    ],

    plot_df[
        "Admission flips"
    ]
)


ax.set_ylabel(
    "Admission-status flips"
)


ax.set_xlabel(
    "Omitted dimension"
)


ax.set_title(
    "LODO ablation — admission impact"
)


ax.tick_params(
    axis="x",
    rotation=25
)


ax.grid(
    True,
    axis="y",
    alpha=0.25
)


save_figure(

    fig,

    "ablation_admission_flips"
)


# ============================================================
# 24. ABLATION FIGURE — Δ ADMITTED
# ============================================================

fig, ax = plt.subplots(
    figsize=(8.2, 4.8)
)


ax.bar(

    plot_df[
        "Omitted dimension display"
    ],

    plot_df[
        "Delta admitted"
    ]
)


ax.axhline(
    0.0,
    linewidth=1.0
)


ax.set_ylabel(
    "Δ admitted clients vs baseline"
)


ax.set_xlabel(
    "Omitted dimension"
)


ax.set_title(
    "LODO ablation — change in admitted clients"
)


ax.tick_params(
    axis="x",
    rotation=25
)


ax.grid(
    True,
    axis="y",
    alpha=0.25
)


save_figure(

    fig,

    "ablation_delta_admitted"
)


# ============================================================
# 25. ABLATION BOX PLOT — ΔHPS
# ============================================================

box_data = []

box_labels = []


for dim in DIMENSIONS:


    vals = (

        ablation_detail_df.loc[

            ablation_detail_df[
                "Omitted dimension"
            ]
            == dim,

            "Delta HPS"
        ]

        .astype(float)

        .values
    )


    box_data.append(
        vals
    )


    box_labels.append(
        DISPLAY[dim]
    )


fig, ax = plt.subplots(
    figsize=(9.2, 5.2)
)


ax.boxplot(
    box_data,
    tick_labels=box_labels
)


ax.axhline(
    0.0,
    linewidth=1.0
)


ax.set_ylabel(
    "ΔHPS after omitting dimension"
)


ax.set_xlabel(
    "Omitted dimension"
)


ax.set_title(
    "LODO ablation — HPS effect distribution"
)


ax.tick_params(
    axis="x",
    rotation=25
)


ax.grid(
    True,
    axis="y",
    alpha=0.25
)


save_figure(

    fig,

    "ablation_delta_hps_boxplot"
)


# ============================================================
# 26. COMPACT THRESHOLD TABLE
# ============================================================

threshold_compact = threshold_summary_df[

    [
        "Threshold mode",
        "Threshold perturbation",
        "Applied T_R",
        "Applied T_A",
        "T_C_direct",
        "T_C_review",
        "Valid policy",
        "Admitted",
        "Delta admitted",
        "Not admitted",
        "Delta not admitted",
        "Admission flips",
        "Lost admissions",
        "New admissions",
        "Admitted-set Jaccard",
        "Direct auto-accept",
        "Review accept",
        "Remediate",
        "Auto-reject",
    ]

].copy()


threshold_compact.to_csv(

    ANALYSIS_DIR
    / "10_threshold_sensitivity_compact.csv",

    index=False
)


# ============================================================
# 27. COMPACT WEIGHT TABLE
# ============================================================

weight_compact = weight_summary_df[

    [
        "Perturbed dimension display",
        "Weight perturbation",
        "New target weight",
        "Admitted",
        "Delta admitted",
        "Not admitted",
        "Delta not admitted",
        "Admission flips",
        "Lost admissions",
        "New admissions",
        "Admitted-set Jaccard",
        "Direct auto-accept",
        "Review accept",
        "Remediate",
        "Auto-reject",
    ]

].copy()


weight_compact.to_csv(

    ANALYSIS_DIR
    / "11_weight_sensitivity_compact.csv",

    index=False
)


# ============================================================
# 28. COMPACT ABLATION RANKING
# ============================================================

ablation_ranking = ablation_summary_df[

    [
        "Omitted dimension display",
        "Was critical dimension",
        "Admitted",
        "Delta admitted",
        "Not admitted",
        "Admission flips",
        "Lost admissions",
        "New admissions",
        "Admitted-set Jaccard",
        "Mean |ΔHPS|",
        "Max |ΔHPS|",
    ]

].copy()


ablation_ranking.to_csv(

    ANALYSIS_DIR
    / "12_ablation_ranking_compact.csv",

    index=False
)


# ============================================================
# 29. IDENTIFY MOST IMPACTFUL DIMENSIONS
# ============================================================

most_admission_impact = (
    ablation_summary_df.iloc[0]
)


most_score_impact = (

    ablation_summary_df

    .sort_values(
        "Mean |ΔHPS|",
        ascending=False
    )

    .iloc[0]
)


critical_only = (

    ablation_summary_df[

        ablation_summary_df[
            "Was critical dimension"
        ]
        == True

    ]

    .sort_values(

        [
            "Admission flips",
            "Mean |ΔHPS|"
        ],

        ascending=False
    )
)


if not critical_only.empty:

    most_critical_impact = (
        critical_only.iloc[0]
    )

else:

    most_critical_impact = None


# ============================================================
# 30. KEY FINDINGS TEXT
# ============================================================

findings_lines = [

    "TADP v11.7 Governance Sensitivity and Ablation Analysis",

    "=" * 72,

    f"Baseline clients: {BASE_N}",

    f"Baseline admitted: {BASE_ADMITTED}",

    f"Baseline not admitted: {BASE_NOT_ADMITTED}",


    (

        f"Baseline thresholds: "

        f"T_R={T_R0:.2f}, "

        f"T_A={T_A0:.2f}, "

        f"T_C_direct={T_C_DIRECT0:.2f}, "

        f"T_C_review={T_C_REVIEW0:.2f}, "

        f"C_min={C_MIN0:.2f}"
    ),


    "",


    "Interpretation safeguards:",


    (
        "- Percent perturbations are robustness/stress tests, "
        "not newly optimized policies."
    ),


    (
        "- C_min remains fixed at ADEQUATE=3 because it is "
        "an ordinal semantic non-compensatory safeguard."
    ),


    (
        "- T_C_direct follows T_A."
    ),


    (
        "- T_C_review remains (T_R + T_A)/2."
    ),


    (
        "- Weight perturbations preserve sum(weights)=1 "
        "by proportional rescaling."
    ),


    (
        "- LODO removes the omitted dimension from HPS and, "
        "when applicable, from the critical set."
    ),


    "",


    (

        "Greatest observed LODO admission impact: "

        f"{most_admission_impact['Omitted dimension display']} "

        f"({int(most_admission_impact['Admission flips'])} "
        f"admission flips; "

        f"Δ admitted="
        f"{int(most_admission_impact['Delta admitted']):+d})."
    ),


    (

        "Greatest observed LODO mean absolute HPS impact: "

        f"{most_score_impact['Omitted dimension display']} "

        f"(mean |ΔHPS|="
        f"{float(most_score_impact['Mean |ΔHPS|']):.4f})."
    ),
]


if most_critical_impact is not None:

    findings_lines.append(

        (

            "Greatest observed admission impact among dimensions "
            "designated critical: "

            f"{most_critical_impact['Omitted dimension display']} "

            f"({int(most_critical_impact['Admission flips'])} "
            "admission flips)."
        )
    )


findings_lines.extend([

    "",

    (
        "Do not interpret these rankings as universal "
        "causal importance."
    ),

    (
        "They describe observed sensitivity in this "
        "controlled 20-client experimental cohort."
    ),
])


key_findings_path = (
    ANALYSIS_DIR
    / "13_key_findings.txt"
)


key_findings_path.write_text(

    "\n".join(
        findings_lines
    ),

    encoding="utf-8"
)


# ============================================================
# 31. ANALYSIS MANIFEST
# ============================================================

manifest = {

    "analysis_name":
        (
            "TADP-Sec v11.7 Governance "
            "Sensitivity and Ablation Analysis"
        ),


    "source_admission_results":
        str(
            ADMISSION_JSON
        ),


    "source_admission_results_sha256":
        sha256_file(
            ADMISSION_JSON
        ),


    "n_clients":
        BASE_N,


    "baseline_admitted":
        BASE_ADMITTED,


    "baseline_not_admitted":
        BASE_NOT_ADMITTED,


    "baseline_weights":
        BASE_WEIGHTS,


    "baseline_critical_dimensions":
        list(
            BASE_CRITICAL
        ),


    "baseline_thresholds": {

        "T_R":
            T_R0,

        "T_A":
            T_A0,

        "T_C_direct":
            T_C_DIRECT0,

        "T_C_review":
            T_C_REVIEW0,

        "C_min":
            C_MIN0,
    },


    "perturbations":

        [
            float(x)
            for x
            in PERTURBATIONS
        ],


    "threshold_sensitivity_modes": [

        "lower_only",

        "upper_only",

        "joint_same_relative_change",
    ],


    "weight_sensitivity":

        (
            "one_dimension_at_a_time_relative_perturbation_"
            "with_proportional_rescaling_of_other_weights_"
            "to_sum_one"
        ),


    "joint_sensitivity":

        (
            "joint_same_direction_threshold_perturbation_"
            "x_one_dimension_weight_perturbation"
        ),


    "ablation":

        (
            "leave_one_dimension_out_then_renormalize_"
            "remaining_weights; if omitted dimension is critical "
            "it is also removed from the critical set"
        ),


    "c_min_sensitivity":

        (
            "not_performed; C_min fixed at "
            "semantic ADEQUATE=3"
        ),


    "monte_carlo":

        "not_performed",


    "baseline_replay_matches_saved_results":
        True,
}


with (

    ANALYSIS_DIR
    / "14_analysis_manifest.json"

).open(
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        manifest,
        f,
        indent=2
    )


# ============================================================
# 32. PRINT THRESHOLD RESULTS
# ============================================================

print(
    "\n"
    + "=" * 88
)

print(
    "ANALYSIS COMPLETE"
)

print(
    "=" * 88
)


print(
    "\nTHRESHOLD SENSITIVITY SUMMARY"
)


print(

    threshold_compact.to_string(

        index=False,

        float_format=
            lambda x:
                (
                    f"{x:.4f}"
                    if pd.notna(x)
                    else "NA"
                )
    )
)


# ============================================================
# 33. PRINT WEIGHT SCENARIOS THAT CHANGED ADMISSION
# ============================================================

print(
    "\n"
    + "=" * 88
)

print(
    "WEIGHT SENSITIVITY — SCENARIOS WITH ADMISSION FLIPS"
)

print(
    "=" * 88
)


weight_changed = weight_compact[

    weight_compact[
        "Admission flips"
    ]
    > 0
]


if weight_changed.empty:

    print(

        "No admission-status flips occurred under the tested "
        "one-at-a-time weight perturbations."
    )


else:

    print(

        weight_changed.to_string(

            index=False,

            float_format=
                lambda x:
                    f"{x:.4f}"
        )
    )


# ============================================================
# 34. PRINT ABLATION RANKING
# ============================================================

print(
    "\n"
    + "=" * 88
)

print(
    "LEAVE-ONE-DIMENSION-OUT ABLATION RANKING"
)

print(
    "=" * 88
)


print(

    ablation_ranking.to_string(

        index=False,

        float_format=
            lambda x:
                f"{x:.4f}"
    )
)


# ============================================================
# 35. PRINT KEY FINDINGS
# ============================================================

print(
    "\n"
    + "=" * 88
)

print(
    "KEY FINDINGS"
)

print(
    "=" * 88
)


print(

    key_findings_path.read_text(
        encoding="utf-8"
    )
)


# ============================================================
# 36. ZIP COMPLETE ANALYSIS PACKAGE
# ============================================================

archive_base = (
    "/content/"
    "TADP_v11_7_governance_"
    "sensitivity_ablation_analysis"
)


archive_path = shutil.make_archive(

    archive_base,

    "zip",

    root_dir=
        ANALYSIS_DIR.parent,

    base_dir=
        ANALYSIS_DIR.name,
)


archive_size_mb = (

    Path(
        archive_path
    ).stat().st_size

    / (1024 ** 2)
)


print(
    "\n"
    + "=" * 88
)

print(
    "ANALYSIS PACKAGE CREATED"
)

print(
    "=" * 88
)


print(
    f"Analysis folder:\n{ANALYSIS_DIR}"
)


print(
    f"\nAnalysis ZIP:\n{archive_path}"
)


print(
    f"\nZIP size: "
    f"{archive_size_mb:.2f} MB"
)


# ============================================================
# 37. DOWNLOAD IS INTENTIONALLY SEPARATE
# ============================================================

print("\nSensitivity/ablation analysis finished.")
print("Run the separate download cell to package/download the analysis folder.")
