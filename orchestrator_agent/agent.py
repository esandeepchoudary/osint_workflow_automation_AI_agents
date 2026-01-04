from google.adk.agents.llm_agent import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.tools import ToolContext
from dotenv import load_dotenv
import os
import pandas as pd
import sys

load_dotenv()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from whois_agent.agent import whois_execution as get_connected_domains
    from bbot_agent.agent import run_bbot
    from email_breach_check_agent.agent import invoke_breachcheck
    from reporting_agent.agent import reporting_start_function
except ImportError as e:
    # This might happen if run in isolation without proper path
    print(f"Orchestrator Import Error: {e}")

def path_for_output_files(session_id: str):
    cwd = os.getcwd()
    global output_path
    output_path = os.path.join(cwd,"OSINT_Files",session_id)
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    return output_path

def extract_emails_for_breach_check(tool_context: ToolContext, path: str):
    session_id = getattr(tool_context.session, "id")
    print(
        "\n*************\n"
        "extract_emails_for_breach_check invoked\n"
        "*************\n"
    )
    project_folder = path_for_output_files(session_id)
    with open(os.path.join(project_folder, 'bbot_emails.txt'), 'r') as file:
        data = file.readlines()
    emails = []
    for i in data:
        emails.append(i.strip())  
    return set(emails)

root_agent = Agent(
    model=LiteLlm(model="groq/openai/gpt-oss-120b", timeout = 10000, api_key=os.getenv('GROQ_API_KEY')),
    name="root_agent",
    description=("An agent that orchestrates multiple OSINT agents to perform comprehensive reconnaissance on a given target."),
    instruction=("""
    You are the OSINT Orchestrator Agent. Your goal is to receive instructions from the user to execute the best tool to accomplish the task the user provides.
    You support two modes of execution:
        1. Workflow mode: In this mode, your goal is execute the workflow defined in the "### Workflow Steps:" section to gather OSINT findings for a given root domain.
        2. Agentic mode: If the user only needs a certain operation to be performed using the tools at your disposal, you can choose the best tool for the purpose to accomplish the given task and return the resuslst to the user.
    
    You can describe the functionality you offer inlcuding the two operating modes to the user along with example queries for the user to understand your purpose.

    To accomplish the given task you can only use the tools that are provided to you.
    Do not generate your own commands or code to perform the task.
    
    
    You have access to the following specialized tools:
    1. `get_connected_domains(domain)`: from Whois Agent. Finds related domains given a root domain of an organization.
    2. `run_bbot(domain_list)`: from BBOT Agent. Scans for subdomains, emails, and cloud assets. Returns a list of events (bbot_output).
    3. `extract_emails_for_breach_check`: Helper to parse emails from BBOT output. This function extracts email addresses found in the bbot scan which can be used as input for the next step i.e. to identify if an email was part of a previous breach.
    4. `invoke_breachcheck(email_list)`: from BreachCheck Agent. Checks emails for known breaches.
    5. `reporting_start_function`: from Reporting Agent. Generates a DOCX report.
    
    ### Workflow Steps:
    1. **Receive the Target**: The user will provide a root domain (e.g., "example.com").
    
    2. **Discovery**:
       - Call `get_connected_domains` with the root domain.
       - You will receive a list of connected domains.
    
    3. **Reconnaissance**:
       - Call `run_bbot` with the list of domains found in Step 2.
       - You will receive a detailed list of events.
    
    4. **Email Extraction**:
       - Call `extract_emails_for_breach_check` function to get a list of email addresses.
       - You will receive a list of email addresses.
       
    5. **Breach Check**:
       - If emails were found, call `invoke_breachcheck` with the list of emails.
       - If no emails found, skip this step.
       
    6. **Reporting**:
       - Invoke `reporting_start_function` function.
       - The tool will return a path to the generated report.
    
    7. **Final Response**:
       - Report the success to the user and provide the path to the DOCX file returned by `create_report`.
    
    ### Constraints:
    - Do NOT make up data.
    - If a step fails (returns error/empty), note it in the summary and proceed if possible.
    - Pass the *exact* output from one tool to the next as specified. Do not try to summarize large JSONs yourself; pass the object.
    """),
    tools=[
        get_connected_domains,
        run_bbot,
        extract_emails_for_breach_check,
        invoke_breachcheck,
        reporting_start_function
    ]
)