from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
import os
import time
from dotenv import load_dotenv

load_dotenv()

llm = ChatAnthropic(
    model="claude-sonnet-4-5",
    max_tokens=1500,
    anthropic_api_key=os.getenv("ANTHROPIC_API_KEY")
)

prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a senior software engineer agent.
Your only job is to rewrite code with all security and quality issues fixed.

Follow these rules:
- Fix ALL security vulnerabilities identified
- Fix ALL quality issues identified
- Keep the same functionality and logic
- Add proper error handling
- Add docstrings and type hints
- Use best practices for the language
- Add comments explaining important changes
- Do NOT use markdown formatting
- Do NOT use backticks in your response
- Use plain text only

Format your response exactly like this:
CHANGES_MADE:
- [change 1]
- [change 2]

FIXED_CODE:
[complete fixed code here]"""),
    ("human", """Rewrite this {language} code with all issues fixed.

Security Issues Found:
{security_findings}

Quality Issues Found:
{quality_findings}

Original Code:
{code}""")
])

chain = prompt | llm | StrOutputParser()

def fix_agent(state: dict) -> dict:
    """
    Fix Agent
    Rewrites the submitted code with all security
    and quality issues fixed.
    Adds fixed code to shared state.
    Includes retry logic for API failures.
    """
    print("[Fix Agent] Rewriting code with fixes applied...")

    max_retries = 3
    for attempt in range(max_retries):
        try:
            state["fixed_code"] = chain.invoke({
                "language": state["language"],
                "code": state["code"],
                "security_findings": state["security_findings"],
                "quality_findings": state["quality_findings"]
            })
            print("[Fix Agent] Code rewrite complete.")
            return state
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"[Fix Agent] Attempt {attempt + 1} failed: {e}. Retrying in 5 seconds...")
                time.sleep(5)
            else:
                print(f"[Fix Agent] All retries failed: {e}")
                state["fixed_code"] = "Code fix unavailable due to API error."
                return state