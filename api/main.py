from agent.llm_client import analyze_vulnerabilities

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os, json
from dotenv import load_dotenv
from mem0 import MemoryClient
from agent.tools_semgrep import run_semgrep, read_file_snippet, remediation_hint
from agent.github_utils import clone_repo, delete_repo
from agent.tools_semgrep import run_semgrep
from agent.iac_scanner import run_checkov_scan



load_dotenv()

#  Initialize FastAPI app\
app = FastAPI(title="AI Code Scanner API", version="1.0")

#  Initialize Mem0 Cloud Client
memory_client = MemoryClient(api_key=os.getenv("MEM0_API_KEY", "m0-your-api-key"))

#  MODELS 
class ScanRequest(BaseModel):
    path: str

class GithubScanRequest(BaseModel):
    repo_url: str




@app.get("/")
def home():
    return {"message": " AI Code Scanner API with Mem0 integration active!"}


@app.post("/scan")
async def scan_endpoint(req: ScanRequest):
    """Run a Semgrep scan and store results in Mem0 Cloud."""
    if not os.path.exists(req.path):
        raise HTTPException(status_code=400, detail="Path not found")

    # Run Semgrep and summarize
    scan_result = run_semgrep(req.path)

    if "error" in scan_result:
        raise HTTPException(status_code=500, detail=scan_result["error"])

    #  Always ensure summary key exists
    summary_text = scan_result.get("summary", f"{len(scan_result.get('results', []))} vulnerabilities found")
    results = scan_result.get("results", [])

    try:
        llm_summary = analyze_vulnerabilities(results)
    except Exception as e:
        llm_summary = f"LLM summary unavailable: {str(e)}"

    stored = 0

    #  vulnerability as a memory in Mem0
    for r in results:
        extra = r.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        file_path = r.get("path", "")
        start_line = r.get("start", {}).get("line", 0)
        end_line = r.get("end", {}).get("line", start_line)
        severity = extra.get("severity", "UNKNOWN")
        message = extra.get("message", "")

        # Build readable content
        code_snippet = read_file_snippet(file_path, start_line, end_line)
        remediation = remediation_hint(r.get("check_id"), message)
        cwe = ", ".join(metadata.get("cwe", []))
        owasp = ", ".join(metadata.get("owasp", []))

        content = (
            f"Security issue detected in {file_path} (lines {start_line}-{end_line}):\n"
            f"{message}\nSeverity: {severity}\nCWE: {cwe}\nOWASP: {owasp}\n"
            f"Remediation: {remediation}\n\nCode Snippet:\n{code_snippet.get('snippet','')}"
        )

        messages = [
            {"role": "user", "content": f"Scan report for {file_path}"},
            {"role": "assistant", "content": content}
        ]

        try:
            memory_client.add(
                messages=messages,
                user_id="ai_code_scanner",
                filters={
                    "repo": os.path.basename(req.path),
                    "file": file_path,
                    "severity": severity,
                    "rule_id": r.get("check_id")
                }
            )
            stored += 1
        except Exception as e:
            print(f" Mem0 storage error: {e}")

    #  similar previous results
    related = []
    try:
        related = memory_client.search(
            query=os.path.basename(req.path),
            user_id="ai_code_scanner",
            filters={"repo": os.path.basename(req.path)},
            limit=3
        )
    except Exception as e:
        print(f" Mem0 search error: {e}")

    # Single final return 
    return {
        "status": "success",
        "repository": os.path.basename(req.path),
        "summary": summary_text,
        "llm_analysis": llm_summary,
        "stored_in_mem0": stored,
        "results": results,
        "related_previous_scans": related
    }


@app.post("/scan-github")
async def scan_github_repo(req: GithubScanRequest):
    """Clone a GitHub repo, run scan, and delete it after analysis."""
    
    repo_path = None

    try:
        # 1️⃣ Clone GitHub repo
        repo_path = clone_repo(req.repo_url)

        if not os.path.exists(repo_path):
            raise HTTPException(status_code=500, detail="Failed to clone repository")

        # 2️⃣ Reuse your existing scan logic
        scan_result = run_semgrep(repo_path)

        if "error" in scan_result:
            raise HTTPException(status_code=500, detail=scan_result["error"])

        summary_text = scan_result.get("summary", f"{len(scan_result.get('results', []))} vulnerabilities found")
        results = scan_result.get("results", [])

        # 3️⃣ LLM summary (same as your file scan)
        try:
            llm_summary = analyze_vulnerabilities(results)
        except Exception as e:
            llm_summary = f"⚠ AI summary unavailable: {str(e)}"


        stored = 0

        # 4️⃣ Store each vulnerability in Mem0
        for r in results:
            extra = r.get("extra", {}) or {}
            metadata = extra.get("metadata", {}) or {}
            file_path = r.get("path", "")
            start_line = r.get("start", {}).get("line", 0)
            end_line = r.get("end", {}).get("line", start_line)
            severity = extra.get("severity", "UNKNOWN")
            message = extra.get("message", "")

            code_snippet = read_file_snippet(file_path, start_line, end_line)
            remediation = remediation_hint(r.get("check_id"), message)
            cwe = ", ".join(metadata.get("cwe", []))
            owasp = ", ".join(metadata.get("owasp", []))

            content = (
                f"Security issue detected in {file_path} (lines {start_line}-{end_line}):\n"
                f"{message}\nSeverity: {severity}\nCWE: {cwe}\nOWASP: {owasp}\n"
                f"Remediation: {remediation}\n\nCode Snippet:\n{code_snippet.get('snippet','')}"
            )

            messages = [
                {"role": "user", "content": f"Scan report for {file_path}"},
                {"role": "assistant", "content": content}
            ]

            try:
                memory_client.add(
                    messages=messages,
                    user_id="ai_code_scanner",
                    filters={
                        "repo": os.path.basename(repo_path),
                        "file": file_path,
                        "severity": severity,
                        "rule_id": r.get("check_id")
                    }
                )
                stored += 1
            except Exception as e:
                print(f"Mem0 storage error: {e}")

        # 5️⃣ Fetch related previous scans
        related = []
        try:
            related = memory_client.search(
                query=os.path.basename(repo_path),
                user_id="ai_code_scanner",
                filters={"repo": os.path.basename(repo_path)},
                limit=3
            )
        except Exception as e:
            print(f"Mem0 search error: {e}")

        return {
            "status": "success",
            "repository": os.path.basename(repo_path),
            "summary": summary_text,
            "llm_analysis": llm_summary,
            "stored_in_mem0": stored,
            "results": results,
            "related_previous_scans": related
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        # 6️⃣ Always delete cloned repo after scan
        if repo_path:
            delete_repo(repo_path)


from agent.iac_scanner import run_checkov_scan


@app.post("/scan-iac")
async def scan_iac_repo(req: GithubScanRequest):
    """Clone a GitHub repo, run IaC scan with Checkov, and delete it after analysis."""

    repo_path = None

    try:
        # 1️⃣ Clone GitHub repo
        repo_path = clone_repo(req.repo_url)

        if not os.path.exists(repo_path):
            raise HTTPException(status_code=500, detail="Failed to clone repository")

        # 2️⃣ Run Checkov IaC scan
        iac_scan_result = run_checkov_scan(repo_path)

        if "error" in iac_scan_result:
            raise HTTPException(status_code=500, detail=iac_scan_result["error"])

        failed_checks = iac_scan_result.get("results", {}).get("failed_checks", [])
        passed_checks = iac_scan_result.get("results", {}).get("passed_checks", [])

        summary_text = f"{len(failed_checks)} IaC misconfigurations found"

        # 3️⃣ AI summary (optional like before)
        failed_checks = iac_scan_result.get("results", {}).get("failed_checks", [])

        try:
            llm_summary = analyze_vulnerabilities(failed_checks)
        except Exception as e:
            llm_summary = f"⚠ AI summary unavailable: {str(e)}"

        stored = 0

        # 4️⃣ Store IaC findings in Mem0
        for check in failed_checks:
            file_path = check.get("file_path", "")
            resource = check.get("resource", "")
            severity = check.get("severity", "UNKNOWN")
            check_name = check.get("check_name", "")
            check_id = check.get("check_id", "")
            guideline = check.get("guideline", "")

            content = (
                f"IaC security misconfiguration in {file_path}\n"
                f"Resource: {resource}\n"
                f"Check: {check_name} ({check_id})\n"
                f"Severity: {severity}\n"
                f"Guideline: {guideline}"
            )

            messages = [
                {"role": "user", "content": f"IaC scan report for {file_path}"},
                {"role": "assistant", "content": content}
            ]

            try:
                memory_client.add(
                    messages=messages,
                    user_id="ai_code_scanner",
                    filters={
                        "repo": os.path.basename(repo_path),
                        "file": file_path,
                        "severity": severity,
                        "rule_id": check_id,
                        "type": "iac"
                    }
                )
                stored += 1
            except Exception as e:
                print(f"Mem0 storage error (IaC): {e}")

        # 5️⃣ Fetch related previous IaC scans
        related = []
        try:
            related = memory_client.search(
                query=os.path.basename(repo_path),
                user_id="ai_code_scanner",
                filters={"repo": os.path.basename(repo_path), "type": "iac"},
                limit=3
            )
        except Exception as e:
            print(f"Mem0 search error (IaC): {e}")

        return {
            "status": "success",
            "repository": os.path.basename(repo_path),
            "summary": summary_text,
            "llm_analysis": llm_summary,
            "stored_in_mem0": stored,
            "failed_checks": failed_checks,
            "passed_checks_count": len(passed_checks),
            "related_previous_scans": related
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        # 6️⃣ Always delete cloned repo
           if repo_path:
              delete_repo(repo_path)

    
