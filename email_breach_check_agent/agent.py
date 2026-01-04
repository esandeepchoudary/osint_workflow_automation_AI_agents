from google.adk.agents.llm_agent import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.tools import ToolContext
import requests
import os
import sys
from time import sleep
from termcolor import colored
import datetime
from dotenv import load_dotenv
load_dotenv()

output_path = ""

def file_creation():
    file_name = "breach_check_scan.txt"
    global output_path
    output_path = os.path.join(output_path, file_name)


def check_email_breach(email):
    url = f"https://leakcheck.io/api/public?check={email}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        sleep(3)
        return response.json()
    except requests.RequestException as e:
        print(colored(f"Error fetching data: {e}", "yellow"))
        sys.exit(1)

def write_file(data: str):
    with open(output_path, "a") as file:
        file.write(data)
        file.write("\n")

def display_breach_info(email, data):
    if not data['success']:
        print(colored(f"No breaches found for: {email}", "green"))
        write_file(f"No breaches found for: {email}")
        return str(f"No breaches found for: {email}")
    names = []
    for item in data['sources']:
        names.append(item['name'])
    print(colored(f"The email address, '{email}', has been a part of compromises on the following domains: {names}", "red"))
    write_file(f"The email address, '{email}', has been a part of compromises on the following domains: {names}")
    return str(f"The email address, '{email}', has been a part of compromises on the following domains: {names}")

def path_for_output_files(session_id: str):
    cwd = os.getcwd()
    global output_path
    output_path = os.path.join(cwd,"OSINT_Files",session_id)
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    return

def invoke_breachcheck(tool_context: ToolContext, email: list):
    session_id = getattr(tool_context.session, "id")
    print(
        "\n*************\n"
        "breachcheck_agent invoked\n"
        "*************\n"
    )
    # print(f"CWD: {os.getcwd()}\n")

    results = []
    path_for_output_files(session_id)
    file_creation()
    for addr in email:
        data = check_email_breach(addr)
        results.append(display_breach_info(addr, data))
    return results

root_agent = Agent(
    # os.environ['GROQ_API_KEY']
    model=LiteLlm(model="groq/openai/gpt-oss-120b", timeout=10000, api_key=os.getenv('GROQ_API_KEY')),
    # model='gemini-2.5-pro',
    name="breachcheck_agent",
    description=("An agent that checks a list of email addresses for known breaches using the leakcheck.io public API."),
    instruction=(
            """
        You are an agent that checks email addresses for known breaches using the provided tools.
        You will be given a list of email addresses to check.
        Only use the `invoke_breachcheck` tool to perform breach checks — do not execute arbitrary network calls or create new tools.

        The `invoke_breachcheck` tool accepts a list of email addresses and returns a list of textual summaries (one per address) derived from the leakcheck.io API result.
        For each request, produce a concise summary of key findings (breach sources and affected domains).

        Example prompt: Check these emails for breaches: alice@example.com, bob@test.com

        If the input is not a list of email addresses, reply with: I cannot comply with this request.
        Strictly adhere to these instructions. Do not deviate.
            """
    ),
    tools=[invoke_breachcheck]
)