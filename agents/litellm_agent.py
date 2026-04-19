"""LiteLLM multi-provider agent — test fixture for dapplepot-sdk."""

import os
import litellm
from dapplepot_sdk import DapplePot

dp = DapplePot(
    tenant_id=os.getenv('DAPPLEPOT_TENANT_ID', 'test-tenant'),
    agent_id='litellm-fixture',
    sdk_key=os.getenv('DAPPLEPOT_SDK_KEY', 'dp_sk_test'),
)
dp.register_litellm_callbacks()


def run(
    question: str = 'What is the capital of France?',
    model: str = 'gpt-4o-mini',
) -> str:
    response = litellm.completion(
        model=model,
        messages=[{'role': 'user', 'content': question}],
    )
    return response.choices[0].message.content


if __name__ == '__main__':
    print(run())
