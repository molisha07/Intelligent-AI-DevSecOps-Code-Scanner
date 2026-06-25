# Intelligent AI DevSecOps Code Scanner

An AI-powered DevSecOps static analysis platform that automatically scans codebases (application code and Infrastructure-as-Code) for security vulnerabilities, prioritizes findings using a Large Language Model (LLM), and maintains long-term memory of security bugs using **Mem0 Cloud**.

---

## 🎯 Features

- **Static Application Security Testing (SAST)**: Scans Python/JavaScript code using **Semgrep**.
- **Infrastructure as Code (IaC) Scanning**: Scans Dockerfiles, Terraform scripts, and Kubernetes manifests using **Checkov**.
- **AI-Powered Vulnerability Analysis**: Uses Google Gemini (`gemini-1.5-flash`) via **LangChain** to analyze raw scanner outputs, rank them by severity, and explain how to remediate them.
- **Vulnerability Memory Layer**: Integrates with **Mem0 Cloud** to remember previously detected vulnerabilities, enabling the AI to recall recurring issues.
- **Git Integration**: Automatically clones public GitHub repositories, runs scans, saves findings, and performs clean-ups.

---

## 🛠️ Tech Stack

- **Framework**: FastAPI (Python)
- **ASGI Server**: Uvicorn
- **Security Scanners**: Semgrep, Checkov
- **LLM Engine**: Google Gemini (via LangChain)
- **Memory Storage**: Mem0 Cloud
- **Git Client**: GitPython

---

## 📂 Project Structure

```text
├── api/
│   └── main.py              # FastAPI endpoints (/scan, /scan-github, /scan-iac)
├── agent/
│   ├── agent_runner.py      # LangChain tool definition for running scans
│   ├── github_utils.py      # Repository cloning and directory cleanup
│   ├── iac_scanner.py       # Checkov execution wrapper
│   ├── llm_client.py        # Gemini prompt structure and invocation
│   └── tools_semgrep.py     # Semgrep execution wrapper and file parsing
├── mem/
│   └── mem0_client.py       # Helper functions to interface with Mem0 Cloud
├── rules/
│   └── learned_rules.yaml   # Custom rule definitions
├── sample_repo/
│   └── vulnerable_app.py    # Test repository file containing SQLi and command injection bugs
├── requirements.txt         # Project package dependencies
└── README.md                # Project documentation
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Git installed on your system
- A Gemini API Key
- A Mem0 API Key

### Installation

1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/molisha07/Intelligent-AI-DevSecOps-Code-Scanner.git
   cd Intelligent-AI-DevSecOps-Code-Scanner
   ```

2. Install all required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Configuration

Create a `.env` file in the root directory and configure your keys:

```env
GEMINI_API_KEY=your_gemini_api_key
MEM0_API_KEY=your_mem0_api_key
```

*Note: You can also use `GOOGLE_API_KEY` in place of `GEMINI_API_KEY`.*

### Running the Server

Start the FastAPI application:

```bash
python -m uvicorn api.main:app --reload
```

The application will start running locally at `http://127.0.0.1:8000`.

---

## 🔌 API Endpoints

Once the server is running, you can access the interactive Swagger documentation at `http://127.0.0.1:8000/docs`.

### 1. Scan Local Path (`POST /scan`)
- **Request Body**:
  ```json
  {
    "path": "/path/to/local/codebase"
  }
  ```

### 2. Scan GitHub Repo (`POST /scan-github`)
- **Request Body**:
  ```json
  {
    "repo_url": "https://github.com/username/repository.git"
  }
  ```

### 3. Scan Infrastructure-as-Code (`POST /scan-iac`)
- **Request Body**:
  ```json
  {
    "repo_url": "https://github.com/username/iac-repository.git"
  }
  ```

---

## 🤝 Contributing
Contributions, issues, and feature requests are welcome. Feel free to open a pull request.
