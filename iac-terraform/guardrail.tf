# guardrail.tf — Amazon Bedrock Guardrail for the sentinel-harness.
#
# Mirrors the M4 CDK guardrail: a sensitive-information policy that ANONYMIZEs a
# couple of PII entity types plus two custom regexes that catch secret-shaped
# strings (an AWS access-key pattern and a generic API-token pattern) in both
# prompts and model responses. Paired with an aws_bedrock_guardrail_version so
# the guardrail can be referenced by a pinned, immutable version.
#
# SECURITY NOTE: the regex PATTERNS below are assembled from character classes
# so that NO literal/real credential ever appears in this file. A pattern such
# as "A[KS]IA[0-9A-Z]{16}" is a detector, not a secret; there is no real key
# checked in here. Do not replace these with copy-pasted example keys.

locals {
  # AWS access-key detector. Assembled from char-classes only — this is the
  # canonical shape of an AKIA/ASIA identifier (prefix + 16 upper-alnum chars),
  # never an actual key. Written piecewise to make the "pattern, not secret"
  # intent explicit and grep-safe.
  aws_key_prefix  = "A[KS]IA"      # AKIA (long-term) or ASIA (temporary) prefix
  aws_key_body    = "[0-9A-Z]{16}" # 16 uppercase alphanumeric characters
  aws_key_pattern = "${local.aws_key_prefix}${local.aws_key_body}"

  # Generic secret/token detector: an "sk-"-style prefix followed by >= 20
  # base62 characters (covers many provider API tokens). The "sk-" literal is
  # built from char-classes so no real token prefix+body pair is embedded.
  token_prefix  = "[a-z]{2}-"        # e.g. sk-, pk-, rk-
  token_body    = "[A-Za-z0-9]{20,}" # 20+ base62 chars
  token_pattern = "${local.token_prefix}${local.token_body}"
}

resource "aws_bedrock_guardrail" "sentinel" {
  name        = "${var.name_prefix}-guardrail"
  description = "Sentinel harness guardrail: anonymize PII and secret-shaped strings in prompts and responses."

  blocked_input_messaging   = var.guardrail_blocked_input_messaging
  blocked_outputs_messaging = var.guardrail_blocked_outputs_messaging

  sensitive_information_policy_config {
    # --- PII entities (ANONYMIZE a couple of representative types) ---
    pii_entities_config {
      type   = "EMAIL"
      action = "ANONYMIZE"
    }

    pii_entities_config {
      type   = "AWS_ACCESS_KEY"
      action = "ANONYMIZE"
    }

    # --- Custom regexes for secret-shaped strings ---
    regexes_config {
      name        = "aws-access-key-pattern"
      description = "Detects AWS access-key identifiers (AKIA/ASIA prefix + 16 uppercase alphanumerics). Pattern only; no real key stored."
      pattern     = local.aws_key_pattern
      action      = "ANONYMIZE"
    }

    regexes_config {
      name        = "generic-api-token-pattern"
      description = "Detects generic 'sk-'-style API tokens (2-letter prefix + '-' + 20+ base62 chars). Pattern only; no real token stored."
      pattern     = local.token_pattern
      action      = "ANONYMIZE"
    }
  }

  tags = {
    Component = "guardrail"
  }
}

# Immutable, pinned version of the guardrail above. Reference this ARN+version
# from an agent/runtime rather than the mutable DRAFT.
resource "aws_bedrock_guardrail_version" "sentinel" {
  guardrail_arn = aws_bedrock_guardrail.sentinel.guardrail_arn
  description   = "Initial published version of the sentinel-harness guardrail."
  skip_destroy  = false
}
