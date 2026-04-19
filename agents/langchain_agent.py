"""LangChain ReAct agent — test fixture for dapplepot-sdk."""

import os
from dapplepot_sdk import DapplePot

dp = DapplePot(
    tenant_id=os.getenv('DAPPLEPOT_TENANT_ID', 'test-tenant'),
    agent_id='langchain-fixture',
    sdk_key=os.getenv('DAPPLEPOT_SDK_KEY', 'dp_sk_test'),
)


def run(question: str = 'What is 2 + 2?') -> str:
    from langchain_openai import ChatOpenAI
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import StrOutputParser

    llm = ChatOpenAI(model='gpt-4o-mini')
    prompt = ChatPromptTemplate.from_messages([
        ('system', 'You are a helpful assistant.'),
        ('human', '{question}'),
    ])
    chain = prompt | llm | StrOutputParser()

    return chain.invoke(
        {'question': question},
        config={'callbacks': [dp.callback_handler()]},
    )


if __name__ == '__main__':
    print(run())
