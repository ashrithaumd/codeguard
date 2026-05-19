from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.output_parsers import StrOutputParser
import os
import time
from dotenv import load_dotenv

load_dotenv()

llm = ChatAnthropic(
    model="claude-sonnet-4-5",
    max_tokens=1000,
    anthropic_api_key=os.getenv("ANTHROPIC_API_KEY")
)

prompt = ChatPromptTemplate.from_messages([
    ("system", """You are CodeGuard Assistant, an expert code reviewer.
You have just completed a full code review and have access to all findings.
Your job is to answer follow up questions about the review clearly and helpfully.

You have access to:
- The original code that was reviewed
- Security findings from the security agent
- Quality findings from the quality agent
- Generated unit tests
- Fixed version of the code
- The full review report

Use this context to give accurate, helpful answers.
Be conversational but precise.
If asked to show code, show clean plain text code without markdown symbols.
Do NOT use ** for bold or # for headers in your responses."""),
    ("human", "Here is the full context of the code review:\n\nORIGINAL CODE:\n{code}\n\nSECURITY FINDINGS:\n{security_findings}\n\nQUALITY FINDINGS:\n{quality_findings}\n\nGENERATED TESTS:\n{test_findings}\n\nFIXED CODE:\n{fixed_code}\n\nFULL REPORT:\n{final_report}"),
    ("ai", "I have reviewed all the findings. I am ready to answer any questions you have about this code review. What would you like to know?"),
    MessagesPlaceholder(variable_name="chat_history"),
    ("human", "{user_message}")
])

chain = prompt | llm | StrOutputParser()


def chat_agent(
    user_message: str,
    review_state: dict,
    chat_history: list
) -> tuple[str, list]:
    """
    Chat Agent
    Answers follow up questions about a completed code review.
    Maintains conversation history for multi turn dialogue.

    Args:
        user_message: The user's question
        review_state: The full state from the pipeline (all findings)
        chat_history: List of previous messages in the conversation

    Returns:
        Tuple of (response text, updated chat history)
    """
    print("[Chat Agent] Processing question...")

    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = chain.invoke({
                "code": review_state.get("code", ""),
                "security_findings": review_state.get("security_findings", ""),
                "quality_findings": review_state.get("quality_findings", ""),
                "test_findings": review_state.get("test_findings", ""),
                "fixed_code": review_state.get("fixed_code", ""),
                "final_report": review_state.get("final_report", ""),
                "chat_history": chat_history,
                "user_message": user_message
            })

            chat_history.append(HumanMessage(content=user_message))
            chat_history.append(AIMessage(content=response))

            print("[Chat Agent] Response ready.")
            return response, chat_history

        except Exception as e:
            if attempt < max_retries - 1:
                print(f"[Chat Agent] Attempt {attempt + 1} failed: {e}. Retrying in 5 seconds...")
                time.sleep(5)
            else:
                print(f"[Chat Agent] All retries failed: {e}")
                return "I encountered an error processing your question. Please try again.", chat_history