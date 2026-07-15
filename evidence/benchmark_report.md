# Deployment benchmark — generic SecOps triage

Workload: **6,000 invokes/mo** · 4,000 in + 800 out tokens/invoke · model `sonnet`.

| Mode | Model $/mo | Compute $/mo | **Total $/mo** | Latency floor | Ops hrs/mo | Owns loop? |
|---|--:|--:|--:|--:|--:|:--:|
| AgentCore Harness (managed) ✅ | $144.00 | $12.00 | **$156.00** | 120 ms | 2.0 | platform |
| Raw Bedrock + DIY loop | $144.00 | $73.00 | **$217.00** | 50 ms | 24.0 | you |
| Self-hosted EKS cluster | $144.00 | $1,168.00 | **$1,312.00** | 20 ms | 40.0 | you |

**Headline:** `agentcore_harness` is the cheapest at **$156.00/mo**, saving **$1,156.00/mo (88.1%)** vs. the most expensive mode (`self_hosted_eks`).

> Deterministic model over dated unit prices — verify prices before quoting (see benchmark_models.AS_OF).
> model_usd is identical across modes; the differentiators are compute_usd (who hosts the loop) and ops_hours_per_month (who keeps it running).
