
from typing import List, Dict
import json
import os

from langchain_google_genai import ChatGoogleGenerativeAI  
from langchain_core.messages import SystemMessage, HumanMessage

# Ensure GOOGLE_API_KEY is set if GEMINI_API_KEY is defined in env
if "GEMINI_API_KEY" in os.environ and "GOOGLE_API_KEY" not in os.environ:
    os.environ["GOOGLE_API_KEY"] = os.environ["GEMINI_API_KEY"]

def analyze_vulnerabilities(findings: List[Dict], model: str = "gemini-1.5-flash") -> str:
    """
    Summarizes and prioritizes vulnerabilities using an LLM.
    findings: list of Semgrep result dicts
    """
    if not findings:
        return "No vulnerabilities found."

    # Compact summary of raw findings
    short_summary = json.dumps(findings[:10], indent=2)[:4000]

    # Initialize LLM
    llm = ChatGoogleGenerativeAI(model=model, temperature=0.4) 

    system_prompt = SystemMessage(
        content=(
            "You are ai code scanner agent. "
            "Given Semgrep data, produce a summary report. "
            "how can we fix these vulnerabilities."
        )
    )

    user_prompt = HumanMessage(
        content=f"Here are the Semgrep findings:\n{short_summary}\n\nSummarize and rank by criticality."
    )

    response = llm.invoke([system_prompt, user_prompt])
    return response.content

def llm_generate(prompt: str, model: str = "gemini-1.5-flash") -> str:
    """
    Generates a response from Gemini for a given raw text prompt.
    """
    llm = ChatGoogleGenerativeAI(model=model, temperature=0.4)
    response = llm.invoke([HumanMessage(content=prompt)])
    return response.content

