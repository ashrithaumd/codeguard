from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
import os
import time
from dotenv import load_dotenv

load_dotenv()

llm = ChatAnthropic(
    model="claude-sonnet-4-5",
    max_tokens=800,
    anthropic_api_key=os.getenv("ANTHROPIC_API_KEY")
)

prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a code quality expert agent. Your only job is to review code for quality issues.

Look for:
- Poor naming conventions
- Missing error handling
- Code complexity and readability issues
- Code duplication or redundancy
- Missing comments and documentation
- Poor code structure and organization
- Performance inefficiencies

You will also receive security findings from a previous agent.
Do NOT repeat security issues. Focus only on quality issues.

Format your response exactly like this:
QUALITY_SCORE: [1-10]
ISSUES:
- [issue 1]
- [issue 2]
RECOMMENDATIONS:
- [fix 1]
- [fix 2]

If no issues found, say QUALITY_SCORE: 10 and ISSUES: None found."""),
    ("human", """Review this {language} code for quality issues.

Security findings already identified (do not repeat these):
{security_findings}

Code to review:
{code}""")
])

chain = prompt | llm | StrOutputParser()

def quality_agent(state: dict) -> dict:
    """
    Code Quality Agent
    Reviews code for best practices, readability, and maintainability.
    Reads security findings from state and adds quality findings.
    Includes retry logic for API failures.
    """
    print("[Quality Agent] Reviewing code quality...")

    max_retries = 3
    for attempt in range(max_retries):
        try:
            state["quality_findings"] = chain.invoke({
                "language": state["language"],
                "code": state["code"],
                "security_findings": state["security_findings"]
            })
            print("[Quality Agent] Review complete.")
            return state
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"[Quality Agent] Attempt {attempt + 1} failed: {e}. Retrying in 5 seconds...")
                time.sleep(5)
            else:
                print(f"[Quality Agent] All retries failed: {e}")
                state["quality_findings"] = "Quality review unavailable due to API error."
                return state