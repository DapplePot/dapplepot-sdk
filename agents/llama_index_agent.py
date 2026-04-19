"""LlamaIndex query + agent — test fixture for dapplepot-sdk."""

import os
from dapplepot_sdk import DapplePot

dp = DapplePot(
    tenant_id=os.getenv('DAPPLEPOT_TENANT_ID', 'test-tenant'),
    agent_id='llama-index-fixture',
    sdk_key=os.getenv('DAPPLEPOT_SDK_KEY', 'dp_sk_test'),
)
dp.instrument_llama_index()


def run(query: str = 'What are the refund conditions?') -> str:
    from llama_index.core import VectorStoreIndex, Document

    docs = [
        Document(text='Refunds are available within 30 days of purchase.'),
        Document(text='Items must be in original condition to qualify for a refund.'),
    ]
    index = VectorStoreIndex.from_documents(docs)
    engine = index.as_query_engine()
    response = engine.query(query)
    return str(response)


if __name__ == '__main__':
    print(run())
    dp.uninstrument_llama_index()
