import json
import os
import pandas as pd
from transformers import RobertaModel, AutoTokenizer, AutoModel
import torch
from sklearn.metrics.pairwise import cosine_similarity
import ast

from sentence_transformers import SentenceTransformer, util


def check_file_vuln(title):
    for file in sorted(os.listdir("../datasets/campaign_graph")):
        with open(f"../datasets/campaign_graph/{file}", "rb") as json_file:
            json_object = json.load(json_file)

            if title in json_object["pdf_title"]:
                print("file name: ", file)


def check_names(check):
    if check == 'validation':
        for i in range(2):
            for j in range(4):
                print(f"Temperature: {i}, Prompt: {j}")
                for file in os.listdir(
                        f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/validation/comb_{i}_{j}'):
                    with open(
                            f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/validation/comb_{i}_{j}/{file}',
                            'rb') as json_file:
                        json_object = json.load(json_file)

                        if len(json_object['nodes']['campaign']) > 1 or len(json_object['nodes']['APT']) > 1:
                            print(file)
    elif check == 'test':
        for i in range(2):
            for j in range(10):
                print(f"Temperature: {i}, Iteration: {j}")
                for file in os.listdir(
                        f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/test/comb_{i}/3_{j}'):
                    with open(
                            f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/test/comb_{i}/3_{j}/{file}',
                            'rb') as json_file:
                        json_object = json.load(json_file)

                        if len(json_object['nodes']['campaign']) > 1 or len(json_object['nodes']['APT']) > 1:
                            print(file)


def check_dates(check):
    if check == 'validation':
        for i in range(2):
            for j in range(4):
                print(f"Temperature: {i}, Prompt: {j}")
                for file in os.listdir(
                        f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/validation/comb_{i}_{j}'):
                    with open(
                            f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/validation/comb_{i}_{j}/{file}',
                            'rb') as json_file:
                        json_object = json.load(json_file)

                        dates = json_object['nodes']['campaign'][0]['date_start']

                        for date in dates:
                            if len(date.split('-')) > 2:
                                print(date)
    elif check == 'test':
        for i in range(2):
            for j in range(4):
                print(f"Temperature: {i}, Iteration: {j}")
                for file in os.listdir(
                        f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/test/comb_{i}/3_{j}'):
                    with open(
                            f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/test/comb_{i}/3_{j}/{file}',
                            'rb') as json_file:
                        json_object = json.load(json_file)

                        dates = json_object['nodes']['campaign'][0]['date_start']

                        for date in dates:
                            if len(date.split('-')) > 2:
                                print(date)


def check_equality():
    for i in range(2):
        print(f"Temperature: {i}")
        for file in os.listdir(
                f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/validation/comb_{i}_3'):
            with open(f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/validation/comb_{i}_3/{file}',
                      'rb') as json_file:
                print(f"File: {file}")
                json_object = json.load(json_file)

                if json_object['nodes']['campaign'][0]['actor'] != json_object['nodes']['APT'][0]['name']:
                    print("Campaign actor: ", json_object['nodes']['campaign'][0]['actor'])
                    print("Actor name: ", json_object['nodes']['APT'][0]['name'])


def check_ground_truth_names():
    for file in sorted(os.listdir(
            f'/Users/manu/PycharmProjects/LlmTI/datasets/campaign_graph/')):
        with open(f'/Users/manu/PycharmProjects/LlmTI/datasets/campaign_graph/{file}', 'rb') as json_file:
            print(f"File: {file}")
            json_object = json.load(json_file)

            print(json_object['nodes']['campaign'][0]['actor'])
            print(json_object['nodes']['APT'][0]['name'])
            print("\n")


def check_similarity(check):
    if check == 'validation':
        df_file = pd.read_excel(
            f"/Users/manu/PycharmProjects/LlmTI/results/campaign_graph/metrics/{check}/results_0_3.xlsx")

        df_file['sim_APT'] = df_file['sim_APT'].apply(lambda x: ast.literal_eval(x) if pd.notna(x) else x)
        df_file['sim_APT'] = df_file['sim_APT'].str[0]

        print(df_file['sim_APT'])

        print(len(df_file[df_file['sim_APT'] < 0.80]['sim_APT']))

    elif check == 'test':
        for temperature in [0, 1]:
            print("Temperature: ", temperature)
            for i in range(10):
                print("Iteration: ", i)
                df_file = pd.read_excel(
                    f"/Users/manu/PycharmProjects/LlmTI/results/campaign_graph/metrics/{check}/results_{temperature}_3_{i}.xlsx")

                df_file['sim_APT'] = df_file['sim_APT'].apply(lambda x: ast.literal_eval(x) if pd.notna(x) else x)
                df_file['sim_APT'] = df_file['sim_APT'].str[0]

                print(len(df_file[df_file['sim_APT'] < 0.80]['sim_APT']))


def check_vulnerability():
    vulnerability_column = list(df_final['vulnerability'].str.lower())
    attack = list(set([vuln for vuln in vulnerability_column if not vuln.startswith('cve')]))

    print("All the attacks: ", attack)


def check_secondary_source():
    df_final = pd.read_excel(
        '/Users/manu/PycharmProjects/LlmTI/data_preprocessing/discard_pdfs/rel_threatactor_vulnerabilities_final.xlsx')

    secondary = df_final.drop_duplicates(subset=["name", "date_start"])
    print(secondary['secondary source pdf'].count())
    print(secondary['secondary source'].count())


if __name__ == '__main__':
    df_final = pd.read_excel(
        '/Users/manu/PycharmProjects/LlmTI/data_preprocessing/discard_pdfs/rel_threatactor_vulnerabilities_final.xlsx')

    check_file_vuln("operation applejeus_ lazarus hits cryptocurrency exchange with fake installer and macos malware _ securelist.pdf")
    """
    vulnerability_column = list(df_final['vulnerability'].str.lower())
    attack = list(set([vuln for vuln in vulnerability_column if not vuln.startswith('cve')]))

    # check_similarity('test')
    # check_ground_truth_names()

    check_secondary_source()
    """
