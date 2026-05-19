import logging
from langgraph.graph import StateGraph, START, END
from typing import TypedDict
from agents.security_agent import security_agent
from agents.quality_agent import quality_agent
from agents.test_agent import test_agent
from agents.fix_agent import fix_agent
from agents.summary_agent import summary_agent
from utils import detect_language
from database import init_db, save_review
from guardrails.validators import validate_input, check_pii, validate_output

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("langgraph").setLevel(logging.WARNING)

init_db()


class CodeReviewState(TypedDict):
    code: str
    language: str
    security_findings: str
    quality_findings: str
    test_findings: str
    fixed_code: str
    final_report: str


graph = StateGraph(CodeReviewState)

graph.add_node("security_agent", security_agent)
graph.add_node("quality_agent", quality_agent)
graph.add_node("test_agent", test_agent)
graph.add_node("fix_agent", fix_agent)
graph.add_node("summary_agent", summary_agent)

graph.add_edge(START, "security_agent")
graph.add_edge("security_agent", "quality_agent")
graph.add_edge("quality_agent", "test_agent")
graph.add_edge("test_agent", "fix_agent")
graph.add_edge("fix_agent", "summary_agent")
graph.add_edge("summary_agent", END)

codeguard_pipeline = graph.compile()


def run_pipeline(code: str) -> dict:
    """
    Main function to run the full CodeGuard pipeline.
    Runs guardrails before pipeline starts.
    Auto detects language from submitted code.
    Saves review to database after completion.
    Returns the final state with all findings and report.
    """
    is_valid, message = validate_input(code)
    if not is_valid:
        return {
            "error": message,
            "code": code,
            "language": "",
            "security_findings": "",
            "quality_findings": "",
            "test_findings": "",
            "fixed_code": "",
            "final_report": ""
        }

    pii_found = check_pii(code)

    language = detect_language(code)
    print(f"[Pipeline] Detected language: {language}")

    initial_state = {
        "code": code,
        "language": language,
        "security_findings": "",
        "quality_findings": "",
        "test_findings": "",
        "fixed_code": "",
        "final_report": ""
    }

    print("[Pipeline] Starting CodeGuard review...")
    result = codeguard_pipeline.invoke(initial_state)

    is_valid, validated_report = validate_output(result["final_report"])
    if not is_valid:
        result["final_report"] = "Report generation failed. Please try again."

    if pii_found:
        result["pii_warning"] = pii_found

    save_review(result)
    print("[Pipeline] Review complete and saved.")
    return result