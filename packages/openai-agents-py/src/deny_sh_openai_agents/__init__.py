"""deny_sh_openai_agents -- wrap a deny.sh vault entry as an OpenAI Agents SDK tool.

The credential is resolved + consumed inside the tool boundary; only a narrowed
DTO is returned to the agent. A fail-closed leak sweep guarantees the raw secret
never crosses back into the model context.

    from deny_sh_openai_agents import deny_vault_tool
    from pydantic import BaseModel

    class InvoiceArgs(BaseModel):
        id: str

    invoice_tool = deny_vault_tool(
        label="stripe-prod",
        password=os.environ["VAULT_PW"],
        name="get_invoice",
        description="Look up a Stripe invoice by id",
        args_schema=InvoiceArgs,            # a pydantic BaseModel
        use=lambda secret, args: {...},     # returns a narrowed DTO
    )

    agent = Agent(name="Billing", tools=[invoice_tool])
"""

from .core import (
    DenyLeakError,
    DenyToolError,
    create_vault_resolver,
    is_narrowed,
)
from .tool import deny_vault_tool

__all__ = [
    "deny_vault_tool",
    "create_vault_resolver",
    "is_narrowed",
    "DenyToolError",
    "DenyLeakError",
]

__version__ = "0.1.0"
