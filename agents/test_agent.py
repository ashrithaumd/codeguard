from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
import os
import time
from dotenv import load_dotenv

load_dotenv()

llm = ChatAnthropic(
    model="claude-sonnet-4-5",
    max_tokens=4096,
    anthropic_api_key=os.getenv("ANTHROPIC_API_KEY")
)

prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a test engineer agent. Your only job is to write unit tests for the given code.

Follow these rules:
- Write tests using the appropriate testing framework for the language
  (pytest for Python, Jest for JavaScript, JUnit for Java)
- Cover normal cases, edge cases, and error cases
- Each test must have a clear descriptive name
- Add a brief comment explaining what each test checks
- Tests must be ready to run without modification
- Do not test for security or quality issues, only functionality
- Do NOT use markdown formatting
- Do NOT use backtick code fences in your response
- Use plain text only

Format your response exactly like this:
TESTING_FRAMEWORK: [framework name]
TEST_COUNT: [number of tests]
TESTS:
[complete test code here]"""),
    ("human", "Write unit tests for this {language} code:\n\n{code}")
])

chain = prompt | llm | StrOutputParser()

def test_agent(state: dict) -> dict:
    """
    Test Generator Agent
    Reads the submitted code and generates unit tests for it.
    Adds generated tests to shared state.
    Includes retry logic for API failures.
    """
    print("[Test Agent] Generating unit tests...")

    max_retries = 3
    for attempt in range(max_retries):
        try:
            state["test_findings"] = chain.invoke({
                "language": state["language"],
                "code": state["code"]
            })
            print("[Test Agent] Tests generated.")
            return state
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"[Test Agent] Attempt {attempt + 1} failed: {e}. Retrying in 5 seconds...")
                time.sleep(5)
            else:
                print(f"[Test Agent] All retries failed: {e}")
                state["test_findings"] = "Test generation unavailable due to API error."
                return state