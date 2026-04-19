"""Raw OpenAI function-calling loop — test fixture for dapplepot-sdk."""

import json
import os
from dapplepot_sdk import DapplePot
from dapplepot_sdk.openai import openai, _patch

dp = DapplePot(
    tenant_id=os.getenv('DAPPLEPOT_TENANT_ID', 'test-tenant'),
    agent_id='openai-fixture',
    sdk_key=os.getenv('DAPPLEPOT_SDK_KEY', 'dp_sk_test'),
)
_patch(dp)

TOOLS = [
    {
        'type': 'function',
        'function': {
            'name': 'get_weather',
            'description': 'Get current weather for a city.',
            'parameters': {
                'type': 'object',
                'properties': {'city': {'type': 'string'}},
                'required': ['city'],
            },
        },
    }
]


def get_weather(city: str) -> dict:
    return {'city': city, 'temperature': '22°C', 'condition': 'sunny'}


def run(question: str = 'What is the weather in Paris?') -> str:
    messages = [{'role': 'user', 'content': question}]

    with dp.session() as session:
        while True:
            response = openai.chat.completions.create(
                model='gpt-4o-mini',
                messages=messages,
                tools=TOOLS,
            )
            choice = response.choices[0]
            messages.append(choice.message)

            if choice.finish_reason == 'tool_calls':
                for tc in choice.message.tool_calls:
                    args = json.loads(tc.function.arguments)
                    result = get_weather(**args)
                    messages.append({
                        'role': 'tool',
                        'tool_call_id': tc.id,
                        'content': json.dumps(result),
                    })
            else:
                return choice.message.content


if __name__ == '__main__':
    print(run())
