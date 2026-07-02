"""
Scenario 3 — Detection-rule generation with adversarial review + publish gate
==============================================================================
Layer 1 (Strategy Iteration) · detection engineering.

Mirrors the customer flow "auto-generate detection rule -> multi-round agent
cross-review -> human merge". Demonstrates the generation != evaluation principle:
a *generator* harness writes a Sigma rule, a separate *adversarial-reviewer* harness
attacks it (false-positive sources, logic gaps), then a human-in-the-loop publish
gate requires analyst sign-off before the rule goes live.

Two independent harnesses (generator + reviewer) = the cheapest, most reliable way
to catch a generator's own blind spots. All generic; runnable on a dev account.
"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sentinel_harness import core as sh

RESULT = {"scenario": "detection_gen_adversarial_review", "steps": []}
def rec(step, data):
    RESULT["steps"].append({"step": step, "data": json.loads(json.dumps(data, default=str))})
    print(f"[..] {step}: {json.dumps(data, default=str)[:240]}")

GEN_SYS = ("You are a detection engineer. Given a threat behavior, write ONE concise Sigma "
           "detection rule (YAML): title, logsource, detection (selection + condition), "
           "level. Keep it tight. Output only the YAML rule.")
REV_SYS = ("You are an adversarial detection reviewer. Attack the given Sigma rule: list "
           "concrete false-positive sources, logic gaps, and evasion bypasses. Then return a "
           "verdict line: 'VERDICT: approve' or 'VERDICT: revise' with a one-line reason. "
           "Be skeptical — your job is to find what's wrong.")

PUBLISH_GATE = sh.tool_inline(
    "request_publish_approval",
    "Request analyst sign-off before publishing a detection rule to production. "
    "Carries the rule and the reviewer verdict; the analyst may hand-merge edits.",
    {"type": "object",
     "properties": {"rule_title": {"type": "string"}, "reviewer_verdict": {"type": "string"},
                    "rule_yaml": {"type": "string"}},
     "required": ["rule_title", "reviewer_verdict"]})

THREAT = ("Detect an npm package running a postinstall script that reads private-key material "
          "(e.g. accessing ~/.ssh, wallet keystores, or environment secrets) during install.")

def build():
    gen = sh.create_harness("sentinel_detect_gen", GEN_SYS,
                            model=sh.bedrock_model(sh.MODEL_SONNET), max_iterations=6)
    rev = sh.create_harness("sentinel_detect_reviewer", REV_SYS,
                            model=sh.bedrock_model(sh.MODEL_SONNET), max_iterations=6)
    # publisher harness holds the HITL publish gate
    pub = sh.create_harness(
        "sentinel_detect_publisher",
        "You are a detection-publishing coordinator. Given a rule and a reviewer verdict, if the "
        "verdict approves, call request_publish_approval to get analyst sign-off before publishing. "
        "Never publish without the human gate.",
        model=sh.bedrock_model(sh.MODEL_SONNET), tools=[PUBLISH_GATE], max_iterations=6)
    for h in (gen, rev, pub): sh.wait_ready(h["harnessId"])
    rec("built", {"gen": gen["harnessId"], "reviewer": rev["harnessId"], "publisher": pub["harnessId"]})
    return gen["arn"], rev["arn"], pub["arn"]

def run(gen_arn, rev_arn, pub_arn):
    # 1) generator writes a rule
    g = sh.invoke(gen_arn, sh.new_session("gen"), f"Threat behavior: {THREAT}")
    rule = g["text"].strip()
    rec("generated_rule", {"rule_head": rule[:300]})

    # 2) adversarial reviewer attacks it (separate harness = independent judgment)
    rv = sh.invoke(rev_arn, sh.new_session("rev"), f"Review this Sigma rule:\n{rule}")
    verdict = rv["text"].strip()
    approved = "approve" in verdict.lower().split("verdict:")[-1][:40] if "verdict:" in verdict.lower() else "approve" in verdict.lower()
    rec("adversarial_review", {"verdict_tail": verdict[-400:], "approved_signal": approved})

    # 3) publish gate — must hit the human-in-the-loop inline_function
    p = sh.invoke(pub_arn, sh.new_session("pub"),
                  f"Rule:\n{rule}\n\nReviewer verdict:\n{verdict}\n\nProceed through the publish approval flow.")
    rec("publish_flow", {"stop_reason": p["stop_reason"], "tools_used": p["tools_used"],
        "reply_head": p["text"][:240]})

    RESULT["verdict"] = {
        "generator_and_reviewer_are_separate_harnesses": True,
        "adversarial_review_ran": bool(verdict),
        "hit_publish_human_gate": "request_publish_approval" in p["tools_used"],
        "note": "generation != evaluation: an independent reviewer harness attacks the generated "
                "rule, and a human gate signs off before publish. Kills self-approval bias."}
    return RESULT

if __name__ == "__main__":
    g, r, p = build(); run(g, r, p)
    out = os.path.join(os.path.dirname(__file__), "..", "evidence", "detection_gen_result.json")
    json.dump(RESULT, open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print("\nsaved evidence/detection_gen_result.json  ·  verdict:", RESULT.get("verdict"))
