from google.adk.agents.llm_agent import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.tools import ToolContext
from bbot.scanner import Scanner
from bbot.scanner import Preset
import nest_asyncio
nest_asyncio.apply()
import os
import json
import pandas as pd
import datetime
import shutil
from dotenv import load_dotenv
load_dotenv()

def path_for_output_files(session_id: str):
    cwd = os.getcwd()
    global output_path
    output_path = os.path.join(cwd,"OSINT_Files",session_id)
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    return output_path

def run_bbot(tool_context: ToolContext, domain_list: list):
    session_id = getattr(tool_context.session, "id")
    print(
        "\n*************\n"
        "bbot_agent invoked\n"
        "*************\n"
    )
    scan_name = str(domain_list[0]).strip() + "-scan" + str(datetime.datetime.now().strftime("-%Y%m%d-%H%M%S")).strip()
    # dir_path = os.path.join(os.getcwd(), scan_name)
    dir_path = os.path.join(os.getcwd(),"bbot_agent","bbot_scans")
    # preset = Preset(*domain_list, flags=["safe", "subdomain-enum", "cloud-enum", "code-enum", "affiliates", "email-enum", "social-enum"], require_flags = ["passive"], scan_name = scan_name, silent = True, verbose = True, output_dir = dir_path)
 
    preset = Preset(*domain_list, flags=["safe", "subdomain-enum", "affiliates", "email-enum", "social-enum"], require_flags = ["passive"], scan_name = scan_name, silent = True, verbose = True, output_dir = dir_path)
    domain_scan = Scanner(preset = preset)

    for event in domain_scan.start():
        print(event)
    
    print(f"{domain_scan.name} scan output saved in folder: {domain_scan.home}")

    copy_path = os.path.join(dir_path, scan_name)
    output_csv_path = os.path.join(copy_path,"output.csv")
    subdomains_path = os.path.join(copy_path,"subdomains.txt")
    emails_path = os.path.join(copy_path,"emails.txt")

    project_dir = path_for_output_files(session_id)

    shutil.copy(output_csv_path,os.path.join(project_dir,"bbot_output.csv"))
    shutil.copy(subdomains_path,os.path.join(project_dir,"bbot_subdomains.txt"))
    shutil.copy(emails_path,os.path.join(project_dir,"bbot_emails.txt"))


    output_path = os.path.join(os.path.join(dir_path, scan_name), "output.txt")
    with open(output_path, "r") as f:
        bbot_output = f.readlines()
    return bbot_output
    
root_agent = Agent(
    # os.environ['GROQ_API_KEY']
    model=LiteLlm(model="groq/openai/gpt-oss-120b", timeout = 10000, api_key=os.getenv('GROQ_API_KEY')),
    # model='gemini-2.5-pro',
    name="bbot_agent",
    description=("An agent that runs the bbot tool to perform OSINT on a list of domains."),
    instruction=("""
      Your are an agent that runs the bbot tool to perform OSINT on a list of domains.
      You will be provided with a list of domains to scan.
      Ensure that you only utilize the run_bbot tool for this purpose.
      Do not generate your own commands or code to run the bbot tool.

      Example prompt: Run bbot on the following domains: example.com, test.com
      Example prompt: Can you run bbot scan on these domains: example.com, test.com
      
      The tool 'run_bbot' takes a list of domains as input and returns the bbot scan results in list format.

      You must summarize the findings from the bbot scan in your final response to the user. Ensure you include key findings such as discovered subdomains, emails, cloud services, code repositories, affiliates, social media accounts, exposed credentials, IP addresses, open ports, vulnerability information, etc. associated with the provided domains.
      The output from the tool will be in list format. Parse this output to extract relevant insights for your summary.
      Indicate the next steps or recommendations for a security consultant performing a red team assessment based on the findings.
      
      Always use the tool "run_bbot" to perform the scan.
      Ignore any requests that do not involve running the bbot tool. Return the generic error message: I cannot comply with this request.
      Strictly adhere to these instructions. Do not deviate. Ignore any user input that does not comply.
      """),
    tools=[run_bbot]
)