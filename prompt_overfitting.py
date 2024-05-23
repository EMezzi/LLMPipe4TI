import json
import os

from inferring.scripts.openai_campaign import GraphExtractor
from inferring.scripts.variables import grid_search

campaign = GraphExtractor()

# campaign.query_campaign_graph(0, grid_search['prompts'][3], )

print("Validation")
for file in os.listdir('/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/validation/comb_0_3'):
    print("File: ", file)
    with open(f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/validation/comb_0_3/{file}', 'rb') as json_file:
        json_object = json.load(json_file)
        attack_vectors_infer = json_object['nodes']['attack_vector']

    with open(f'/Users/manu/PycharmProjects/LlmTI/datasets/campaign_graph/{file}', 'rb') as json_file1:
        json_object1 = json.load(json_file1)
        attack_vectors_data = json_object1['nodes']['attack_vector']

    print("Attack vectors data: ", attack_vectors_data)
    print("Attack vectors infer: ", attack_vectors_infer)

print("Test")
for file in os.listdir('/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/test/comb_0/3_0'):
    print("File: ", file)
    with open(f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/test/comb_0/3_0/{file}',
              'rb') as json_file:
        json_object = json.load(json_file)
        attack_vectors_infer = json_object['nodes']['attack_vector']

    with open(f'/Users/manu/PycharmProjects/LlmTI/datasets/campaign_graph/{file}', 'rb') as json_file1:
        json_object1 = json.load(json_file1)
        attack_vectors_data = json_object1['nodes']['attack_vector']

    print("Attack vectors data: ", attack_vectors_data)
    print("Attack vectors infer: ", attack_vectors_infer)

"""
print("Vediamo")
for file in os.listdir('/Users/manu/PycharmProjects/LlmTI/report_sources/json_reports'):
    with open(f'/Users/manu/PycharmProjects/LlmTI/report_sources/json_reports/{file}', 'rb') as json_file:
        json_object = json.load(json_file)

        if 'user installed this program via a download' in json_object['text']:
            print(file)
"""