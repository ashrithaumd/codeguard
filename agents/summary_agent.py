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

SYSTEM_PROMPT = (
    "You are a senior engineering lead agent. Your job is to compile all findings "
    "from the security, quality, and test agents into one clean structured report. "
    "Do NOT use markdown formatting. "
    "Do NOT use ** for bold. "
    "Do NOT use # for headers. "
    "Use plain text only. Use CAPS for emphasis instead. "
    "Format your response exactly like this:\n\n"
    "CODEGUARD REVIEW REPORT\n"
    "=======================\n"
    "LANGUAGE: [language]\n\n"
    "OVERALL SCORE: [1-10]\n\n"
    "SECURITY REVIEW\n"
    "---------------\n"
    "[security findings here in plain text]\n\n"
    "QUALITY REVIEW\n"
    "--------------\n"
    "[quality findings here in plain text]\n\n"
    "GENERATED TESTS\n"
    "---------------\n"
    "[test findings here in plain text]\n\n"
    "FIXED CODE SUMMARY\n"
    "------------------\n"
    "[brief summary of what was fixed]\n\n"
    "SUMMARY\n"
    "-------\n"
    "[2-3 sentence executive summary of overall code health]\n\n"
    "PRIORITY ACTIONS\n"
    "----------------\n"
    "1. [most important fix]\n"
    "2. [second most important fix]\n"
    "3. [third most important fix]"
)

prompt = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_PROMPT),
    ("human", (
        "Compile this full code review report.\n\n"
        "Language: {language}\n\n"
        "Security Findings:\n{security_findings}\n\n"
        "Quality Findings:\n{quality_findings}\n\n"
        "Generated Tests:\n{test_findings}\n\n"
        "Fixed Code:\n{fixed_code}"
    ))
])

chain = prompt | llm | StrOutputParser()

def summary_agent(state: dict) -> dict:
    """
    Summary/Report Agent
    Compiles all findings from previous agents into a clean report.
    Produces the final output shown to the user.
    Includes retry logic for API failures.
    """
    print("[Summary Agent] Compiling final report...")

    max_retries = 3
    for attempt in range(max_retries):
        try:
            state["final_report"] = chain.invoke({
                "language": state["language"],
                "security_findings": state["security_findings"],
                "quality_findings": state["quality_findings"],
                "test_findings": state["test_findings"],
                "fixed_code": state["fixed_code"]
            })
            print("[Summary Agent] Report ready.")
            return state
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"[Summary Agent] Attempt {attempt + 1} failed: {e}. Retrying in 5 seconds...")
                time.sleep(5)
            else:
                print(f"[Summary Agent] All retries failed: {e}")
                state["final_report"] = "Report generation unavailable due to API error."
                return state