"""Raw Anthropic tool-use loop — test fixture for dapplepot-sdk."""

import json
import os
from dapplepot_sdk import DapplePot
from dapplepot_sdk.anthropic import anthropic, _patch

dp = DapplePot(
    tenant_id=os.getenv('DAPPLEPOT_TENANT_ID', 'test-tenant'),
    agent_id='anthropic-fixture',
    sdk_key=os.getenv('DAPPLEPOT_SDK_KEY', 'dp_sk_test'),
)
_patch(dp)

TOOLS = [
    {
        'name': 'summarise_document',
        'description': 'Summarise a document given its text.',
        'input_schema': {
            'type': 'object',
            'properties': {'text': {'type': 'string'}},
            'required': ['text'],
        },
    }
]


def summarise_document(text: str) -> str:
    return f'Summary: {text[:80]}...'


def run(content: str = 'Summarise this contract.') -> str:
    client = anthropic.Anthropic()
    messages = [{'role': 'user', 'content': content}]

    with dp.session() as session:
        while True:
            response = client.messages.create(
                model='claude-sonnet-4-20250514',
                max_tokens=1024,
                tools=TOOLS,
                messages=messages,
            )
            messages.append({'role': 'assistant', 'content': response.content})

            if response.stop_reason == 'tool_use':
                tool_results = []
                for block in response.content:
                    if block.type == 'tool_use':
                        result = summarise_document(**block.input)
                        tool_results.append({
                            'type': 'tool_result',
                            'tool_use_id': block.id,
                            'content': result,
                        })
                messages.append({'role': 'user', 'content': tool_results})
            else:
                for block in response.content:
                    if hasattr(block, 'text'):
                        return block.text
                return ''


if __name__ == '__main__':
    print(run())
