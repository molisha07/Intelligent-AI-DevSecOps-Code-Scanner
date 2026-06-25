
from langchain.tools import Tool
from langchain.agents import initialize_agent, AgentType
from langchain_google_genai import ChatGoogleGenerativeAI
from agent.tools_semgrep import run_semgrep
from agent.llm_client import llm_generate

# Define a Tool for Semgrep
def semgrep_tool_func(target_dir: str) -> str:
    data = run_semgrep(target_dir, rule_dir="rules")
    return str(data)  # simplified: return text response

semgrep_tool = Tool(
    name="SemgrepScanner",
    func=semgrep_tool_func,
    description="Run semgrep on a codebase and return JSON results."
)

# LLM wrapper for LangChain using Google Gemini:
# llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", temperature=0)
# If using custom local LLM
def run_scan_and_summarize(target_dir: str):
    semgrep_output = run_semgrep(target_dir, rule_dir="rules")
    # Create a prompt that includes semgrep_output (summarize top results)
    prompt = f"Summarize semgrep findings and suggest fixes:\n\n{semgrep_output}"
    llm_response = llm_generate(prompt)
    return {"semgrep": semgrep_output, "summary": llm_response}
