import json

import pandas as pd
import ast

from results.scripts.metrics_calculation import MetricsCalculator
import numpy as np
from variables import grid_search, json_validation_campaign
from data_preprocessing.scripts.preprocessing_json import Preprocessor
from openai_campaign import GraphExtractor
from graph_alignment import GraphAligner
import os


def avg_dict_filling(list_d, keys_cat):
    avg_dict = {}

    for d in list_d:
        for key in d.keys():
            avg_dict[key] = {}
            avg_dict[key]['pr'], avg_dict[key]['rec'], avg_dict[key]['f1'], avg_dict[key]['sim'] = [], [], [], []
            for key_cat in keys_cat:
                avg_dict[key]['pr'].append(d[key][key_cat]['pr'])
                avg_dict[key]['rec'].append(d[key][key_cat]['rec'])
                avg_dict[key]['f1'].append(d[key][key_cat]['f1'])
                avg_dict[key]['sim'].append(d[key][key_cat]['sim'])

            avg_dict[key]['pr'] = round(np.mean(avg_dict[key]['pr']), 2)
            avg_dict[key]['rec'] = round(np.mean(avg_dict[key]['rec']), 2)
            avg_dict[key]['f1'] = round(np.mean(avg_dict[key]['f1']), 2)
            avg_dict[key]['sim'] = round(np.mean(avg_dict[key]['sim']), 2)

    return avg_dict


if __name__ == '__main__':
    # json_files = os.listdir('/Users/manu/PycharmProjects/LlmTI/inferring/inferred_json_graphs/campaign_graph/')
    # sampled = random.sample(json_files, 174)

    ga = GraphAligner()

    choice = 'campaign'

    if choice == 'campaign':
        list_d = []
        for i, temperature in enumerate(grid_search['temperature']):
            print(f"Temperature: {temperature}")
            # for j, prompt in enumerate(grid_search['prompts']):
                # print(f"Prompt: {prompt}")
            # GraphExtractor.main_campaign_graph(f'/Users/manu/PycharmProjects/LlmTI/datasets/campaign_graph', f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/validation/comb_{i}_3', json_validation_campaign, temperature, prompt)
            """
            Preprocessor.preprocess_json_campaign_graph(f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/validation/comb_{i}_3')
            """

            """
            ga.main_graph_alignment(f'/Users/manu/PycharmProjects/LlmTI/datasets/campaign_graph',
                                    f'/Users/manu/PycharmProjects/LlmTI/inferring/campaign_graph/validation/comb_{i}_3',
                                    f'/Users/manu/PycharmProjects/LlmTI/results/campaign_graph/similarities/validation/comb_{i}_3')

            Preprocessor.build_csv_from_json_similarities('/Users/manu/PycharmProjects/LlmTI/datasets/campaign_graph',
                                                          f'/Users/manu/PycharmProjects/LlmTI/results/campaign_graph/similarities/validation/comb_{i}_3',
                                                          f'/Users/manu/PycharmProjects/LlmTI/results/campaign_graph/metrics/validation/results_{i}_3.xlsx',
                                                          choice)
            """

            MetricsCalculator.main_metrics(f'/Users/manu/PycharmProjects/LlmTI/results/campaign_graph/metrics/validation/results_{i}_3.xlsx',
                                           list_d, choice, 0.80, 0, i, 3)

        for d in list_d:
            print(d)

        keys_cat_nodes = ['campaign', 'APT', 'vulnerability', 'vector']
        avg_dict = avg_dict_filling(list_d, keys_cat_nodes)

        print("Nodes")
        for key in avg_dict.keys():
            print(f"Key: {key}")
            print(avg_dict[key])

        keys_cat_rel = ['attr_to', 'targets', 'employs']
        avg_dict = avg_dict_filling(list_d, keys_cat_rel)

        print("Relations")
        for key in avg_dict.keys():
            print(f"Key: {key}")
            print(avg_dict[key])
                
    elif choice == 'context':
        print("Choice is: ", choice)

        sampled_context = os.listdir('/Users/manu/PycharmProjects/LlmTI/datasets/context_graph')

        print("Sampled context: ", len(sampled_context))

        # index = sampled_context.index('12.json')

        temperatures = [0.00, 1.00]
        for i, temperature in enumerate(temperatures):
            list_d = []
            print(f"Temperature: {temperature}")
            """
            llm_infer_context('/Users/manu/PycharmProjects/LlmTI/datasets/context_graph',
                              f'/Users/manu/PycharmProjects/LlmTI/inferring/context_graph/validation/comb_{i}',
                              sampled_context, temperature)

            Preprocessor.preprocess_json_context(f'/Users/manu/PycharmProjects/LlmTI/inferring/context_graph/validation/comb_{i}')

            ga.main_graph_alignment('/Users/manu/PycharmProjects/LlmTI/datasets/context_graph',
                                    f'/Users/manu/PycharmProjects/LlmTI/inferring/context_graph/validation/comb_{i}',
                                    f'/Users/manu/PycharmProjects/LlmTI/results/context_graph/similarities/validation/comb_{i}')

            Preprocessor.build_csv_from_json_similarities(f'/Users/manu/PycharmProjects/LlmTI/datasets/context_graph',
                                                          f'/Users/manu/PycharmProjects/LlmTI/results/context_graph/similarities/validation/comb_{i}',
                                                          f'/Users/manu/PycharmProjects/LlmTI/results/context_graph/metrics/validation/results_{i}.xlsx', choice)
            """
            MetricsCalculator.main_metrics(f'/Users/manu/PycharmProjects/LlmTI/results/context_graph/metrics/validation/results_{i}.xlsx', list_d, choice, 0.80, 0.00, i, None)

            print(list_d)

    elif choice == 'dates':

        prompt = """
                    You are a Cyber Threat Analyst. Use the following step-by-step guide to extract information from cyber threat reports. 
                    
                    Step 1 - Find all the dates present in the report.
                    
                    Note: - If there is more than one date list them all. 
                          - Examples of formats in which you will fine the dates: May 2015, 2015/05, 2015
                          - Always convert the dates you find in the format: yyyy-mm. If there is not the month, the month is January.
                    
                    Step 2 - Return the information filling this JSON format: 
                    
                            {
                                "nodes": {
                                    "date_start": ["yyyy-mm", "yyyy-mm", "yyyy-mm"]
                                }
                            }
        """

        files = os.listdir('/Users/manu/PycharmProjects/LlmTI/datasets/campaign_graph')

        for temperature in grid_search['temperature'][1:]:
            print("Temperature: ", temperature)
            for i in range(10):
                print("Iteration: ", i)
                results = pd.read_excel(f'/Users/manu/PycharmProjects/LlmTI/results/campaign_graph/metrics/test/results_{temperature}_3_{i}.xlsx')

                results['sim_campaign'] = results['sim_campaign'].apply(lambda x: ast.literal_eval(x)[0] if pd.notna(x) else x)
                results['sim_APT'] = results['sim_APT'].apply(lambda x: ast.literal_eval(x)[0] if pd.notna(x) else x)
                no_good = results[(results['sim_campaign'] < 1.00) & (results['sim_APT'] >= 0.80)]['json']

                print(no_good)

                for file in no_good:
                    print(f"File: {file}")
                    with open(f'/Users/manu/PycharmProjects/LlmTI/datasets/campaign_graph/{file}', 'rb') as json_file:
                        json_object = json.load(json_file)
                        title = json_object['pdf_title'][0]
                        original_date = json_object['nodes']['campaign'][0]['date_start']

                        with open(f'/Users/manu/PycharmProjects/LlmTI/datasets/pdf_json/{title[:-4]}.json', 'rb') as json_file1:
                            report = json.load(json_file1)['text']
                            answer = GraphExtractor.query_campaign_graph(temperature, prompt, report)

                            if answer:
                                print(answer)
                                print("Original dates: ", original_date)
                                try:
                                    GraphExtractor.save_json(f'/Users/manu/PycharmProjects/LlmTI/inferring/dates/test/comb_{temperature}/3_{i}/{file}', answer.content)
                                    with open(f'/Users/manu/PycharmProjects/LlmTI/inferring/dates/test/comb_{temperature}/3_{i}/{file}', 'rb') as new_file:
                                        new_object = json.load(new_file)
                                except Exception as e:
                                    print(e)












