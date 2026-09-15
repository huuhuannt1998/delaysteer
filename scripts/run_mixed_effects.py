#!/usr/bin/env python3
"""Fit the design's mixed-effects model and the preregistered principal contrasts.

The governing design (section 11, Statistics) asks for paired McNemar *and* a
mixed-effects logistic model with random effects for home, day, automation template
and model, plus a small preregistered contrast set. McNemar and Wilson intervals were
already reported; this closes the modelling half.

Two of the four requested grouping factors exist in this substrate (template, model);
home and day do not -- there is one virtual home plus one live instance, and no
multi-day design -- and that is reported rather than silently dropped.

Writes results/mixed_effects.json.

    python3 scripts/run_mixed_effects.py
"""
from __future__ import annotations

import json
import warnings

import numpy as np
import pandas as pd
import statsmodels.formula.api as smf

warnings.filterwarnings("ignore")

OUT = "results/mixed_effects.json"
report: dict = {
    "note": ("Random effects requested by the design: home, day, template, model. "
             "This substrate has one virtual home plus one live Home Assistant "
             "instance and no multi-day design, so home and day are not axes here "
             "and are omitted rather than faked. Template and model are used."),
}

df = pd.read_csv("results/gar.csv")
# pandas reads an empty call_sequence as NaN, and NaN.astype(str) is "nan", which is
# not "" -- so the obvious filter silently keeps every dead row. Drop NaN explicitly.
df = df[df["call_sequence"].notna() & (df["call_sequence"].astype(str).str.strip() != "")]
df["attack"] = (df["arm"] == "attack").astype(int)
df["y"] = df["realized"].astype(str).str.strip().isin(["1", "True", "true"]).astype(int)
df["viol"] = df["violated"].astype(str).str.strip().isin(["1", "True", "true"]).astype(int)

# The two models that emitted no tool call in either arm are excluded from the paper's
# rates as a function-calling capability gap, so they are excluded from the model too --
# otherwise the fit pools over planners the paper says it dropped.
_act = df.groupby("model")["y"].sum()
EXCLUDED = sorted(_act[_act == 0].index)
df_all = df
df = df[~df["model"].isin(EXCLUDED)].copy()

report["n_runs"] = int(len(df))
report["n_runs_before_exclusion"] = int(len(df_all))
report["n_models"] = int(df["model"].nunique())
report["excluded_models"] = EXCLUDED
report["n_templates"] = int(df["template"].nunique())

# ---- 1. The model the design actually asks for ---------------------------------
# Mixed-effects LOGISTIC with crossed random intercepts for both grouping factors
# that exist in this substrate. Variational-Bayes fit; the point estimate and its
# posterior sd are reported, not a frequentist p-value.
try:
    from statsmodels.genmod.bayes_mixed_glm import BinomialBayesMixedGLM
    vc = {"model": "0 + C(model)", "template": "0 + C(template)"}
    mm = BinomialBayesMixedGLM.from_formula("y ~ attack", vc, df).fit_vb()
    i = list(mm.model.exog_names).index("attack")
    mean, sd = float(mm.fe_mean[i]), float(mm.fe_sd[i])
    report["activation_logistic_mixed"] = {
        "log_odds_attack": round(mean, 4),
        "posterior_sd": round(sd, 4),
        "odds_ratio": round(float(np.exp(mean)), 2),
        "or_ci95": [round(float(np.exp(mean - 1.96 * sd)), 2),
                    round(float(np.exp(mean + 1.96 * sd)), 2)],
        "spec": ("logit(activation) ~ attack, crossed random intercepts for model "
                 "and template; variational Bayes"),
    }
except Exception as exc:
    report["activation_logistic_mixed"] = {"error": str(exc)}

# ---- 1b. Variance components on the LOGIT scale --------------------------------
# The linear-mixed refits below are on the probability scale and are NOT comparable
# with the logistic fit above; quoting them side by side compares two different scales.
try:
    _n = list(mm.model.vcp_names)
    _v = np.asarray(mm.vcp_mean)          # vcp_mean is log-sd
    report["logit_scale_variance_components"] = {
        k: round(float(np.exp(v) ** 2), 5) for k, v in zip(_n, _v)}
except Exception as exc:
    report["logit_scale_variance_components"] = {"error": str(exc)}

# ---- 1c. Does the attack EFFECT differ by planner? -----------------------------
# Random intercepts shift each planner's baseline; they cannot say whether the delay
# effect itself varies. The paper claims it does, so it needs a slope test.
try:
    import statsmodels.api as sm
    from scipy.stats import chi2
    _add = smf.glm("y ~ attack + C(model)", df, family=sm.families.Binomial()).fit()
    _int = smf.glm("y ~ attack * C(model)", df, family=sm.families.Binomial()).fit()
    _lr = 2 * (_int.llf - _add.llf)
    _df = int(_int.df_model - _add.df_model)
    report["slope_heterogeneity_test"] = {
        "spec": "LR test, logit(y) ~ attack*C(model) vs attack + C(model)",
        "lr_stat": round(float(_lr), 2), "df": _df,
        "p": float(chi2.sf(_lr, _df))}
except Exception as exc:
    report["slope_heterogeneity_test"] = {"error": str(exc)}

# ---- 1d. Per-model odds ratios ------------------------------------------------
# With a significant attack x model interaction, the pooled OR summarises a spread it
# does not represent. Report the per-model effects as the primary result.
try:
    import pandas as _pd
    _rows = {}
    for _m in sorted(df["model"].unique()):
        _s = df[df["model"] == _m]
        _t = _pd.crosstab(_s["attack"], _s["y"]).reindex(
            index=[0, 1], columns=[0, 1]).fillna(0).values.astype(float)
        _corr = 0.5 if (_t == 0).any() else 0.0   # Haldane-Anscombe
        _t = _t + _corr
        _or = (_t[1, 1] * _t[0, 0]) / (_t[1, 0] * _t[0, 1])
        _se = float(np.sqrt((1.0 / _t).sum()))
        _rows[_m] = {
            "odds_ratio": round(float(_or), 2),
            "ci95": [round(float(np.exp(np.log(_or) - 1.96 * _se)), 2),
                     round(float(np.exp(np.log(_or) + 1.96 * _se)), 1)],
            "n": int(len(_s)),
            "continuity_correction": bool(_corr),
        }
    report["per_model_odds_ratios"] = _rows
except Exception as exc:
    report["per_model_odds_ratios"] = {"error": str(exc)}

# ---- 2. Single-grouping linear mixed fits, as a sensitivity check ---------------
for group in ("model", "template"):
    try:
        m = smf.mixedlm("y ~ attack", df, groups=df[group]).fit(reml=False)
        beta = float(m.params["attack"])
        se = float(m.bse["attack"])
        report[f"activation_re_{group}"] = {
            "fixed_effect_attack": round(beta, 4),
            "std_err": round(se, 4),
            "z": round(beta / se, 3) if se else None,
            "p": float(m.pvalues["attack"]),
            "ci95": [round(beta - 1.96 * se, 4), round(beta + 1.96 * se, 4)],
            "group_var": round(float(m.cov_re.iloc[0, 0]), 5),
            "n_groups": int(df[group].nunique()),
            "spec": f"y ~ attack + (1|{group}), linear mixed model on the 0/1 outcome",
        }
    except Exception as exc:
        report[f"activation_re_{group}"] = {"error": str(exc)}

# ---- 3. Logistic fit with model fixed, for the odds-ratio reading ---------------
try:
    lg = smf.logit("y ~ attack + C(model)", df).fit(disp=False)
    b = float(lg.params["attack"])
    se = float(lg.bse["attack"])
    report["activation_logit_model_fixed"] = {
        "log_odds_attack": round(b, 4),
        "odds_ratio": round(float(np.exp(b)), 3),
        "or_ci95": [round(float(np.exp(b - 1.96 * se)), 3),
                    round(float(np.exp(b + 1.96 * se)), 3)],
        "p": float(lg.pvalues["attack"]),
        "spec": "logit(y) ~ attack + C(model); model as fixed effect",
    }
except Exception as exc:
    report["activation_logit_model_fixed"] = {"error": str(exc)}

# ---- 4. Preregistered principal contrasts --------------------------------------
# The design names three. DelaySteer vs best-single is not estimable here: the gate
# resolved against composition, so there is no multi-delay arm to contrast against
# the single delay. The other two come from the defense residual matrix.
res = pd.read_csv("results/defense_residual.csv")
res["adm"] = res["admitted"].astype(int)


def contrast(a: str, b: str) -> dict:
    """Admitted-cell counts for two defense arms over the same position x hold grid."""
    x = res[res["defense"] == a].set_index(["position", "hold_s"])["adm"]
    y = res[res["defense"] == b].set_index(["position", "hold_s"])["adm"]
    idx = x.index.intersection(y.index)
    x, y = x.loc[idx], y.loc[idx]
    disc_b = int(((x == 1) & (y == 0)).sum())   # a admits, b blocks
    disc_c = int(((x == 0) & (y == 1)).sum())   # b admits, a blocks
    n = int(len(idx))
    from math import comb
    if disc_b + disc_c:
        k, tot = min(disc_b, disc_c), disc_b + disc_c
        p = min(1.0, 2 * sum(comb(tot, i) for i in range(k + 1)) / 2 ** tot)
    else:
        p = 1.0
    return {"cells": n, f"{a}_admits_only": disc_b, f"{b}_admits_only": disc_c,
            f"{a}_admitted": int(x.sum()), f"{b}_admitted": int(y.sum()),
            "exact_mcnemar_p": round(p, 5)}


report["contrasts"] = {
    "prereg_1_delaysteer_vs_best_single": {
        "status": "not estimable",
        "reason": ("The Stage-2 gate resolved against composition, so there is no "
                   "multi-delay arm to contrast with the best single delay. Reported "
                   "as not estimable rather than as a null."),
    },
    "prereg_2_attested_vs_none": contrast("none", "Attested"),
    "prereg_3_attested_vs_lite": contrast("Lite", "Attested"),
}

with open(OUT, "w") as fh:
    json.dump(report, fh, indent=2)

print(f"  wrote {OUT}")
for k in ("activation_logistic_mixed", "activation_re_model",
          "activation_re_template", "activation_logit_model_fixed"):
    v = report.get(k, {})
    if "error" in v:
        print(f"  {k}: FAILED {v['error'][:60]}")
    else:
        print(f"  {k}: {v}")
for k, v in report["contrasts"].items():
    print(f"  {k}: {v}")
