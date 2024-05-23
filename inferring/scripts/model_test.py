import json
import os

import pandas as pd

from openai_campaign import GraphExtractor
from variables import grid_search, json_test_campaign
from graph_alignment import GraphAligner
from data_preprocessing.scripts.preprocessing_json import Preprocessor
from results.scripts.metrics_calculation import MetricsCalculator

if __name__ == '__main__':

    ga = GraphAligner()

    choice = 'comparison'
    if choice == 'campaign':
        for temperature in grid_search['temperature']:
            print("Temperature: ", temperature)
            list_d = []
            for i in range(10):
                # GraphExtractor.main_campaign_graph(f'/Users/manu/PycharmProjects/LlmTI/datasets/campaign_graph', f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/test/comb_{temperature}/3_{i}', json_test_campaign, temperature, grid_search['prompts'][3])
                # Preprocessor.preprocess_json_campaign_graph(f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/test/comb_{temperature}/3_{i}')

                """
                ga.main_graph_alignment(f'/Users/manu/PycharmProjects/LlmTI/datasets/campaign_graph',
                                        f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/test/comb_{temperature}/3_{i}',
                                        f'/Users/manu/PycharmProjects/LlmTI/results/campaign_graph/similarities/test/comb_{temperature}/3_{i}')

                Preprocessor.build_csv_from_json_similarities(f'/Users/manu/PycharmProjects/LlmTI/datasets/campaign_graph',
                                                              f'/Users/manu/PycharmProjects/LlmTI/results/campaign_graph/similarities/test/comb_{temperature}/3_{i}',
                                                              f'/Users/manu/PycharmProjects/LlmTI/results/campaign_graph/metrics/test/results_{temperature}_3_{i}.xlsx', choice)
                """
                MetricsCalculator.main_metrics(f'/Users/manu/PycharmProjects/LlmTI/results/campaign_graph/metrics/test/results_{temperature}_3_{i}.xlsx',
                                               list_d, 'campaign', 0.80, 0.00, temperature, 3)

            print(list_d)
            main_dict = {}
            keys = ['campaign', 'APT', 'vulnerability', 'vector', 'attr_to', 'targets', 'employs']
            for key in keys:
                main_dict[key] = {}
                main_dict[key]['pr'], main_dict[key]['rec'], main_dict[key]['f1'], main_dict[key]['sim'] = [], [], [], []
                for d in list_d:
                    main_dict[key]['pr'].append(d[(temperature, 3, 0.8)][key]['pr'])
                    main_dict[key]['rec'].append(d[(temperature, 3, 0.8)][key]['rec'])
                    main_dict[key]['f1'].append(d[(temperature, 3, 0.8)][key]['f1'])
                    main_dict[key]['sim'].append(d[(temperature, 3, 0.8)][key]['sim'])

            metrics = ['sim', 'pr', 'rec', 'f1']
            for key in keys:
                for metric in metrics:
                    print(f"Key: {key}, Metric: {metric}, Min: {min(main_dict[key][metric])}, Max: {max(main_dict[key][metric])}")
                print("\n")

    elif choice == 'comparison':

        """
        Create prompt
        """

        prompt = "You are a Cyber Threat Analyst. Use the following step-by-step guide to extract information from cyber threat reports.\n"

        categories_to_extract = ["server", "victim", "related file", "threat actor", "tool", "vulnerability"]

        s = "\nStep 1 - Extract the "
        for i, cat in enumerate(categories_to_extract):
            s += cat
            if i == len(categories_to_extract) - 1:
                s += '.'
            else:
                s += ' if present, '

        prompt += s

        e = "\n\nHere are some examples to help with you understand which entities are vulnerabilities and which are not:"

        s = "\n\nNote:"

        for i, cat in enumerate(categories_to_extract):
            if cat == "server" or "related file" or "tool" or "vulnerability":
                if i > 0:
                    s += f"      - There can more than one {cat}.\n"
                else:
                    s += f" - There can be more than one {cat}.\n"

            if cat == "related file":
                s += f"      - Include also the files at the end of links.\n"
                s += f"      - Include also generic file types. Example: zip archive.\n"""
                s += f"      - Include also file that recall to commands. Example: PowerShell command.\n"""

            if cat == "threat actor":
                s += f"      - Do not include tools as threat actors. Drakon APT is a tool, not a threat actor.\n"

            if cat == "vulnerability":
                s += f"      - Do not include tools as vulnerabilities. Example: Firefox backdoor is a vulnerability. \n"
                s += f"      - Do not include techniques as vulnerabilities. Example: Phishing and Stolen Credentials are not vulnerabilities. Firefox backdoor and JScript backdoor are vulnerabilities.\n"

        prompt += s

        s = "\n\nStep 2 - Return the connections between the entities that you found, in this format (entity1, connection, entity2)"

        prompt += s

        s = "\n\nStep 3 - Return the information filling in this JSON format:\n"
        s += "nodes: {\n"

        for i, cat in enumerate(categories_to_extract):
            if cat != "campaign":
                if i > 0:
                    s += """\n"""

                s += f"""   {cat}: [\n      {{\n        "name": "" // name of the {cat}\n        "id": "" // id of the {cat}\n      }}\n   ]"""

                if i < len(categories_to_extract) - 1:
                    s += ','

        prompt += s

        s = "\n}\nconnections: [(entity1, connection, entity2), (entity, connection, entity), ...]"

        prompt += s
        prompt += '\n}'

        print(prompt)

        for temperature in grid_search['temperature']:
            print("Temperature: ", temperature)
            list_d = []
            for file in os.listdir('/Users/manu/PycharmProjects/LlmTI/datasets/comparison_graph'):
                with open(f'/Users/manu/PycharmProjects/LlmTI/datasets/comparison_graph/{file}', 'rb') as json_file:
                    json_object = json.load(json_file)
                    answer = GraphExtractor.query_campaign_graph(temperature, prompt, json_object['text'])

                    title = json_object['title']
                    if answer:
                        GraphExtractor.save_json(f'/Users/manu/PycharmProjects/LlmTI/inferring/comparison_graph/composed/comb_{temperature}/{title}.json', answer.content)

