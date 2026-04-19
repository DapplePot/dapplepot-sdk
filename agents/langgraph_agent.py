"""LangGraph multi-node agent — test fixture for dapplepot-sdk."""

import os
from typing import TypedDict, Annotated
from dapplepot_sdk import DapplePot

dp = DapplePot(
    tenant_id=os.getenv('DAPPLEPOT_TENANT_ID', 'test-tenant'),
    agent_id='langgraph-fixture',
    sdk_key=os.getenv('DAPPLEPOT_SDK_KEY', 'dp_sk_test'),
)


class State(TypedDict):
    messages: Annotated[list, lambda a, b: a + b]


def run(question: str = 'Summarise last quarter.') -> dict:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import HumanMessage, AIMessage
    from langgraph.graph import StateGraph, END

    llm = ChatOpenAI(model='gpt-4o-mini')

    def research_node(state: State) -> State:
        response = llm.invoke(state['messages'])
        return {'messages': [response]}

    def summarise_node(state: State) -> State:
        summary_prompt = [
            *state['messages'],
            HumanMessage(content='Summarise the above in one sentence.'),
        ]
        response = llm.invoke(summary_prompt)
        return {'messages': [response]}

    graph = StateGraph(State)
    graph.add_node('research', research_node)
    graph.add_node('summarise', summarise_node)
    graph.set_entry_point('research')
    graph.add_edge('research', 'summarise')
    graph.add_edge('summarise', END)
    compiled = graph.compile()

    return compiled.invoke(
        {'messages': [HumanMessage(content=question)]},
        config={'callbacks': [dp.callback_handler()]},
    )


if __name__ == '__main__':
    result = run()
    print(result['messages'][-1].content)
