# deny-sh-langchain

Wrap a [deny.sh](https://deny.sh) vault entry as a LangChain v1 tool (Python).
The credential resolves inside the tool boundary; only a narrowed DTO reaches
the model. Fail-closed leak sweep.

```bash
pip install deny-sh-langchain langchain langchain-openai
```

## Usage

```python
import os
from pydantic import BaseModel
from langchain.agents import create_agent
from langchain_openai import ChatOpenAI
from deny_sh_langchain import deny_vault_tool
import requests

class InvoiceArgs(BaseModel):
    id: str

def lookup(stripe_key: str, args: dict) -> dict:
    r = requests.get(
        f"https://api.stripe.com/v1/invoices/{args['id']}",
        headers={"Authorization": f"Bearer {stripe_key}"},
    )
    body = r.json()
    # narrowed DTO -- never the raw key, never the raw upstream body
    return {"id": body.get("id"), "amount_due": body.get("amount_due"), "status": body.get("status")}

invoice_tool = deny_vault_tool(
    label="stripe-prod",                  # or: id="item_abc"
    password=os.environ["VAULT_PW"],      # server env, never the prompt
    name="get_invoice",
    description="Look up a Stripe invoice by id",
    args_schema=InvoiceArgs,
    use=lookup,
)

agent = create_agent(model=ChatOpenAI(model="gpt-4o"), tools=[invoice_tool])
```

The Stripe key is resolved + consumed entirely inside `lookup`. The agent and
the model provider see only the input args and the narrowed return. The key
never enters the model's context window.

## Multi-tenant

Pass a per-tenant `client_options={"api_key": ...}` and password. One tenant
cannot decrypt another's vault entry; the boundary is cryptographic.

## Config

| Field | Required | Notes |
|-------|----------|-------|
| `label` / `id` | one of | vault entry label, or a stable item id |
| `password` | yes | vault wrap password |
| `name`, `description`, `args_schema` | yes | standard LangChain tool fields (`args_schema` is a pydantic model) |
| `use(secret, args)` | yes | privileged work; return a narrowed DTO |
| `client_options` | no | forwarded to `deny_sh.vault_get` (`api_key`, `base_url`, ...) |
| `leak_sweep` | no | default `True`; fail-closed scan of the returned DTO |

Apache-2.0. Part of [deny-sh-integrations](https://github.com/deny-sh-crypto/deny-sh-integrations).
