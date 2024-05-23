import ast
import os
import json
from scipy import spatial
import shutil

import pandas as pd
from openai import OpenAI
from langchain.text_splitter import SpacyTextSplitter

EMBEDDING_MODEL = 'text-embedding-3-small'
gpt_model = 'gpt-3.5-turbo-1106'

key = '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'
client = OpenAI(api_key=key)

dict_query = {"campaign": {"query": "Extract the starting date of the campaign and the the threat actor responsible "
                                    "for the campaign",
                           "info": """Return the information related to the threat campaign filling this json format: 

                                         "nodes": {
                                            "campaign": [
                                                {
                                                    "actor": "", // name of the threat actor
                                                    "date_start": ["yyyy-mm", "yyyy-mm"], // starting date of the campaign
                                                    "id": "campaign1" // id of the campaign
                                                }
                                            ]
                                        }

                                         Note: - There can be only one campaign. 
                                               - The name of the threat actor can only be one.  
                                               - In case there is more than one date feasible as date of start for the campaign, list them all. 
                                   """
                           },

              "vulnerability": {"query": "Extract the vulnerabilities exploited by the threat actor",
                                "info": """Return the information related to the vulnerabilities filling this json format: 

                                             "nodes": {
                                                "vulnerability": [
                                                    {
                                                        "name": "CVE-xxxx-", // code of the vulnerability                                                  
                                                        "id": "vulnerability1" // id of the vulnerability
                                                    },
                                                    {                                                       
                                                        "name": "CVE-xxxx-", // code of the vulnerability                                                       
                                                        "id": "vulnerability2" // id of the vulnerability
                                                    }
                                                ]
                                            }

                                            Note: - Extract only the CVE which are directly attributed to the threat actor in the report.
                                                  - There can be more that one vulnerability.
                                                  - Each node will have an id, composed by the acronym of the node and the number of the entity.
                                                  - If you do not find any CVE directly attributed to the threat actor, leave the list empty. 
                                        """
                                },

              "attack_vector": {"query": "Extract the attack vectors used by the threat actor in the report",
                                "info": """Return the information related to the attack vectors filling this json format: 
                                            
                                            "nodes": {
                                                "attack_vector": [
                                                    {
                                                        "name": "", // name of the attack vector
                                                        "id": "attack_vector1" // id of the attack vector
                                                    },
                                                    {
                                                        "name": "", // name of the attack vector
                                                        "id": "attack_vector2" // id of the attack vector
                                                    }         
                                                ]
                                            }
                                            
                                            Note: - Give only the general category of the attack vector employed by the actor. General categories are but not limited to: spear-phishing, spear-phishing attachment, drive-by compromise...
                                                  - Only extract the attack vectors which are directly attributed to the actor in the report. 
                                                  - Each node will have an id, composed by the acronym of the node and the number of the entity.
                                                  - If you do not find any attack vectors directly attributed to the actor, leave the list empty. 
                                        """
                                }
              }


def save_json(file_path, object):
    json_object = None
    if isinstance(object, str):
        json_object = json.loads(object)
    elif isinstance(object, dict):
        json_object = object

    if json_object:
        with open(file_path, 'w') as json_file:
            json.dump(json_object, json_file, indent=4)


def get_embedding(text, model="text-embedding-3-small"):
    text = text.replace("\n", " ")
    return client.embeddings.create(input=[text], model=model).data[0].embedding


def tokenization(title, text, text_splitter, dict_embeddings):
    docs = text_splitter.split_text(text)

    for doc in docs:
        dict_embeddings['title'].append(title)
        dict_embeddings['text'].append(doc)
        dict_embeddings['embedding'].append(get_embedding(doc))


def embeddings_generation():
    dict_embeddings = {'title': [], 'text': [], 'embedding': []}
    for file in os.listdir('../datasets/pdf_json/'):
        with open(f'../../datasets/pdf_json/{file}', 'rb') as json_file:
            json_object = json.load(json_file)
            print("File: ", json_object['title'])
            text_splitter = SpacyTextSplitter()
            tokenization(json_object['title'], json_object['text'], text_splitter, dict_embeddings)

    df = pd.DataFrame(dict_embeddings)
    df.to_csv(f'reports_embeddings.csv', index=False)


def strings_ranked_by_relatedness(query, df, title, relatedness_fn=lambda x, y: 1 - spatial.distance.cosine(x, y)):
    """Returns a list of strings and relatednesses, sorted from most related to least."""

    query_embedding_response = client.embeddings.create(model=EMBEDDING_MODEL, input=query)
    query_embedding = query_embedding_response.data[0].embedding

    strings_and_relatednesses = [(row["text"], relatedness_fn(query_embedding, row["embedding"])) for i, row in
                                 df[df['title'] == title].iterrows()]
    strings_and_relatednesses.sort(key=lambda x: x[1], reverse=True)
    strings, relatednesses = zip(*strings_and_relatednesses)

    return strings[:2], relatednesses[:2]


def query_message(query, df, title):
    """Return a message for GPT, with relevant source texts pulled from a dataframe."""
    strings, relatednesses = strings_ranked_by_relatedness(query, df, title)

    threat_report = ""
    for string in strings:
        next_section = f'\n\nSection of the threat report:\n"""\n{string}\n"""'
        threat_report += next_section

    message = query + f" using the following cyber threat report: {threat_report}."

    return message


def query_mini_graph(query, what, df, title, model, print_message=False):
    """Answers a query using GPT and a dataframe of relevant texts and embeddings."""
    message = query_message(query, df, title)
    if print_message:
        print("Message is: ", message)

    messages = [
        {"role": "system", "content": f"""You are a Cyber Threat Analyst, and your role is to extract the requested 
                                          information from cyber threat reports.
                                         
                                          {what}
                                       """
         },
        {"role": "user", "content": message},
    ]

    try:
        response = client.chat.completions.create(model=model, response_format={"type": "json_object"},
                                                  messages=messages, temperature=0)
        return response.choices[0].message
    except Exception as e:
        print(f"Exception: ", e)


def llm_infer_mini_graph():
    """
    With this function we infer the initial campaign graph
    :return:
    """
    # shutil.rmtree('../inferred_json_graphs/mini_graph_embeddings/')
    # os.makedirs('../inferred_json_graphs/mini_graph_embeddings/')

    df_embeddings = pd.read_csv('reports_embeddings.csv')
    df_embeddings['embedding'] = df_embeddings['embedding'].apply(ast.literal_eval)

    for report in os.listdir('../datasets/campaign_graph')[49:]:
        print("Report: ", report)
        with open(f'../../datasets/campaign_graph/{report}', 'rb') as file:
            json_file = json.load(file)

            title = json_file['pdf_title']
            print("The title is: ", title)

            if len(title) == 1:
                answer_campaign = eval(query_mini_graph(dict_query['campaign']['query'],
                                                        dict_query['campaign']['info'],
                                                        df_embeddings,
                                                        title[0][:-4], gpt_model).content)

                answer_vulnerability = eval(query_mini_graph(dict_query['vulnerability']['query'],
                                                             dict_query['vulnerability']['info'],
                                                             df_embeddings,
                                                             title[0][:-4], gpt_model).content)

                answer_attack_vector = eval(query_mini_graph(dict_query['attack_vector']['query'],
                                                             dict_query['attack_vector']['info'],
                                                             df_embeddings,
                                                             title[0][:-4], gpt_model).content)

                answer_campaign['nodes']['APT'] = [{'name': answer_campaign['nodes']['campaign'][0]['actor'], 'id': 'APT1'}]
                answer_campaign['nodes']['vulnerability'] = answer_vulnerability['nodes']['vulnerability']
                answer_campaign['nodes']['attack_vector'] = answer_attack_vector['nodes']['attack_vector']

                if answer_campaign:
                    save_json(f'../inferred_json_graphs/mini_graph_embeddings/{report}', answer_campaign)


if __name__ == '__main__':
    # embeddings_generation()
    llm_infer_mini_graph()
