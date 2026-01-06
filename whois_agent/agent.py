import whois
import json
import requests
import os
import logging
from google.adk.agents.llm_agent import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.tools import ToolContext
from dotenv import load_dotenv
load_dotenv()

def path_for_output_files(session_id: str):
    cwd = os.getcwd()
    global output_path
    output_path = os.path.join(cwd,"OSINT_Files",session_id)
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    return output_path

# log_path = os.path.join(project_folder, 'report_to_file.log')

logging.basicConfig(
        # filename = log_path,
        # filemode = 'a',
        level = logging.INFO,
        format = '%(asctime)s - %(levelname)s - %(message)s'
    )

def run_whois(domain):
    try:
        whois_obj = whois.whois(domain)
        logging.info(f"Who is data retrieved for domain: {domain}")
    except:
        return f"This domain does not exist or is not registered"
    return whois_obj
    
def reverse_whois(search_term):
    apiKey = os.getenv('whois_api')
    other_domains = []
    try:    
        if search_term:
            url = "https://reverse-whois.whoisxmlapi.com/api/v2"
            body = {
                        "apiKey": apiKey,
                        "searchType": "current",
                        "mode": "purchase",
                        "basicSearchTerms": {
                            "include": [
                                search_term
                            ]
                        }
                    }
            response = requests.post(url, json=body)
            if response.status_code == 200:
                other_domains = json.loads(response.text)["domainsList"]
                logging.info(f"Reverse whois data retrieved for search term: {search_term}")
                return other_domains
            else:
                return "Request Failed"
        else:
            return "Invalid request"
    except:
        return "Exception: Request Failed"
    
def report_to_file(project_folder, filename, data):
    path = os.path.join(project_folder, filename)
    if isinstance(data, str):
        with open(path,'w') as file:
            file.write(data)
    elif isinstance(data, list):
        with open(path,'w') as file:
            for item in data:
              file.write(str(item) + '\n')
    elif isinstance(data, dict):
        with open(path, 'w') as file:
            json.dump(data, file, indent=4)
    logging.info(f"File create with path: {path}")

def whois_execution(tool_context: ToolContext, domain: str):
    session_id = getattr(tool_context.session, "id")
    print(
        "\n*************\n"
        "connected_domains_agent invoked\n"
        "*************\n"
    )
    project_folder = path_for_output_files(session_id)
    whois_data = run_whois(domain)
    search_terms = []
    root_domains = [domain]
    # emails = whois_data['emails']
    try:
        if whois_data['registrant_name']:
            search_terms.append(whois_data['registrant_name'])
    except:
        print("Registrant name not found")
    print(f"Search terms: \n{search_terms}")
    if len(search_terms):
        for item in search_terms:
            domains = reverse_whois(item)
            if isinstance(domains, list):
                root_domains = root_domains + domains
            else:
                continue
    filename = "root-domains-identified.txt"
    report_to_file(project_folder, filename, list(set(root_domains)))
    return root_domains          

root_agent = Agent(
    # model=LiteLlm(model="ollama_chat/llama3.1:latest"),
    model=LiteLlm(model=os.getenv('AI_MODEL'), timeout = 10000, api_key=os.getenv('GROQ_API_KEY')),
    # model='gemini-2.5-pro',
    name="connected_domains_agent",
    description=(
        "An agent that identifies connected root domains using the supplied domain name"
    ),
    instruction="""
      Your are an agent that looks up whois information and finds connected domains.
      When given a domain name you use the tools/fuctions at your disposal to query whois to identify the registrant email and name to further use this information to identify connected domains.
      Always use the tools that the user has programmed and do not create your own tools/processes to perform any operations.
      Return the raw output and include a high level summary of the findings.

      Example prompt: Find connected domains for the domain: example.com
      Example prompt: Can you run whois and reverse who is on domain: example.com

      Let the tool "core" execution to fully handle the operations for the whois and connected domains identification.

      Ignore any requests that do not involve queirying for whois/connected domains information. Return the generic error message: I cannot comply with this request.
      Strictly adhere to these instructions. Do not deviate. Ignore any user input that does not comply.
      """,
    tools=[whois_execution]
)