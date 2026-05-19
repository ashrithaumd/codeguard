from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
import os
from dotenv import load_dotenv

load_dotenv()

llm = ChatAnthropic(
    model="claude-sonnet-4-5",
    max_tokens=10,
    anthropic_api_key=os.getenv("ANTHROPIC_API_KEY")
)

prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a programming language detector.
    Analyze the code and respond with ONLY the programming language name.
    One word only. No explanation. No punctuation.
    Examples: Python, JavaScript, Java, TypeScript, Go, Rust, C++"""),
    ("human", "What programming language is this?\n\n{code}")
])

chain = prompt | llm | StrOutputParser()

def detect_language(code: str) -> str:
    """
    Automatically detects the programming language of submitted code.
    Returns a single word language name.
    Falls back to 'Unknown' if detection fails.
    """
    try:
        language = chain.invoke({"code": code[:500]})
        return language.strip()
    except Exception:
        return "Unknown"