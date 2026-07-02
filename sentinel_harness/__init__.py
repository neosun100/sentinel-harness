"""sentinel-harness — production SecOps agents as configuration on Amazon Bedrock AgentCore Harness."""
from .core import (  # noqa: F401
    create_harness, wait_ready, invoke, new_session,
    bedrock_model, tool_code_interpreter, tool_remote_mcp, tool_gateway, tool_inline,
    managed_memory, byo_memory, delete_harness, cleanup, list_harnesses,
    MODEL_SONNET, MODEL_HAIKU, MODEL_OPUS, REGION,
)

__version__ = "0.1.0"
