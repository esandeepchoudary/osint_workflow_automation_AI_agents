# OSINT Agents

A comprehensive OSINT (Open Source Intelligence) framework powered by Agentic AI. This project orchestrates multiple specialized agents to perform deep reconnaissance on target domains, covering discovery, enumeration, breach checking, and reporting.

## Overview

The system operates through a central **Orchestrator Agent** that coordinates the following specialized agents:

- **Whois Agent**: Discovers connected domains using Whois data.
- **BBOT Agent**: Performs active and passive scanning (subdomains, emails, cloud assets) using [BBOT](https://github.com/blacklanternsecurity/bbot).
- **Email Breach Check Agent**: Verifies if discovered email addresses have been compromised in known breaches.
- **Reporting Agent**: Compiles all findings into a structured DOCX report.

## Directory Structure

- `orchestrator_agent/`: Central logic and workflow coordination.
- `whois_agent/`: Domain discovery logic.
- `bbot_agent/`: Reconnaissance utilizing BBOT.
- `email_breach_check_agent/`: Email breach verification.
- `reporting_agent/`: Report generation tools.

## Prerequisites

- Python >= 3.12
- `uv` (recommended) or `pip`

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd osint_agents
    ```

2.  **Install dependencies:**
    Using `uv` (synchronizes dependencies from `pyproject.toml`):
    ```bash
    uv sync
    ```
    Or using `pip`:
    ```bash
    pip install .
    ```

3.  **Environment Setup:**
    Create a `.env` file in the root directory based on `.env.example`:
    ```bash
    cp .env.example .env
    ```
    
    Update `.env` with your API keys:
    ```ini
    whois_api="YOUR_WHOIS_XML_API_KEY"
    GROQ_API_KEY="YOUR_GROQ_API_KEY"
    AI_MODEL="groq/openai/gpt-oss-120b" # or your preferred model supported by LiteLLM

4.  **Install all dependencies required by BBOT:**
    SUDO privileges are required to install some dependencies. Enter your sudo password when prompted.
    ```bash
    source .venv/bin/activate
    uv add aiohttp
    bbot --install-all-deps
    ```

## Usage

The system is designed to be run via the Google ADK (Agent Development Kit).
Use the following command to start the web interface:
```
adk web
```

## Workflow Steps

1.  **Receive Target**: User inputs a root domain.
2.  **Discovery**: `get_connected_domains` identifies related organizational domains.
3.  **Reconnaissance**: `run_bbot` scans valid domains for subdomains and emails.
4.  **Email Extraction**: Parses emails from the BBOT output.
5.  **Breach Check**: `invoke_breachcheck` verifies if emails verify against breach datasets.
6.  **Reporting**: `reporting_start_function` compiles all gathered data into a report.
7.  **Final Response**: Path to the generated DOCX report is returned.
