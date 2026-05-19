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
    ("system", """You are a security expert agent. Your only job is to scan code for security vulnerabilities.

Look for:
- Hardcoded secrets, API keys, or passwords
- SQL injection vulnerabilities
- XSS vulnerabilities
- Insecure imports or libraries
- Exposed sensitive data
- Unsafe user input handling

Format your response exactly like this:
SEVERITY: [HIGH/MEDIUM/LOW/NONE]
ISSUES:
- [issue 1]
- [issue 2]
RECOMMENDATION:
- [fix 1]
- [fix 2]

If no issues found, respond with SEVERITY: NONE and ISSUES: None found."""),
    ("human", "Scan this {language} code for security vulnerabilities:\n\n{code}")
])

chain = prompt | llm | StrOutputParser()

def security_agent(state: dict) -> dict:
    """
    Security Scanner Agent
    Scans submitted code for security vulnerabilities.
    Adds findings to shared state for downstream agents.
    Includes retry logic for API failures.
    """
    print("[Security Agent] Scanning code for vulnerabilities...")

    max_retries = 3
    for attempt in range(max_retries):
        try:
            state["security_findings"] = chain.invoke({
                "language": state["language"],
                "code": state["code"]
            })
            print("[Security Agent] Scan complete.")
            return state
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"[Security Agent] Attempt {attempt + 1} failed: {e}. Retrying in 5 seconds...")
                time.sleep(5)
            else:
                print(f"[Security Agent] All retries failed: {e}")
                state["security_findings"] = "Security scan unavailable due to API error."
                return state