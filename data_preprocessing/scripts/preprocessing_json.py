import json
import pandas
import os
import shutil
import re

import pandas as pd


class Preprocessor:
    @staticmethod
    def change_id(json_object):
        for key in json_object["nodes"].keys():
            for i, el in enumerate(json_object["nodes"][key]):
                el["id"] = key + str(i + 1)

    @staticmethod
    def relations_creation(nodes_relations, starting_key, ending_key, relation_name):
        for starting_node in nodes_relations["nodes"][starting_key]:
            for ending_node in nodes_relations["nodes"][ending_key]:
                nodes_relations["relations"][relation_name].append((starting_node["id"], ending_node["id"]))

    # Preprocess json for context
    @staticmethod
    def preprocess_json_context(path):
        df_aliases = pd.read_excel('/Users/manu/PycharmProjects/LlmTI/neo4j_db/raw_data/Aliases1.xlsx')

        for file in os.listdir(path):
            with open(f'{path}/{file}', 'rb') as json_file:
                print("File: ", file)
                json_object = json.load(json_file)
                Preprocessor.change_id(json_object)

                if not isinstance(json_object['nodes']['APT'][0]['name'], list):
                    json_object['nodes']['APT'][0]['name'] = [json_object['nodes']['APT'][0]['name']]

                list_name = []
                if len(json_object['nodes']['APT']) > 0:
                    for name in json_object['nodes']['APT'][0]['name']:
                        official_name_APT = df_aliases[df_aliases['alias'].str.lower() == name.lower()]['name']
                        if not official_name_APT.empty:
                            official_name = official_name_APT
                            list_name.extend(list(official_name))

                json_object['nodes']['APT'][0]['name'].extend(list_name)
                json_object['nodes']['APT'][0]['name'] = list(set(json_object['nodes']['APT'][0]['name']))

                json_object["relations"] = {"origin": [], "targets": [], "uses": []}
                Preprocessor.relations_creation(json_object, "APT", "country", "origin")
                Preprocessor.relations_creation(json_object, "APT", "vulnerability", "targets")
                Preprocessor.relations_creation(json_object, "APT", "attack_vector", "uses")

                with open(f'{path}/{file}', 'w') as json_file1:
                    json.dump(json_object, json_file1, indent=4)

    @staticmethod
    def preprocess_ground_truth():
        df_final = pd.read_excel('../../data_preprocessing/discard_pdfs/rel_threatactor_vulnerabilities_final.xlsx')

        for file in os.listdir('../../datasets/campaign_graph/'):
            with open(f'../../datasets/campaign_graph/{file}') as json_file:
                print(f"File: {file}")

                json_object = json.load(json_file)

                # function that corrects the ground truth for the vulnerabilities and the attack vectors.
                def fill_ground_truth():
                    if not json_object['nodes']['attack_vector']:
                        if len(json_object['pdf_title']) == 1:
                            print("Attack vector")
                            rows = df_final[(df_final['primary source pdf'] == json_object['pdf_title'][0]) &
                                            (df_final['date_start'] == json_object['nodes']['campaign'][0][
                                                'date_start'])]

                            for attack_vector in rows['vulnerability']:
                                av = attack_vector.lower()
                                if av == 'unknown' and not av.startswith('cve'):
                                    json_object['nodes']['attack_vector'].append({'name': av, 'id': av})

                    if not json_object['nodes']['vulnerability']:
                        if len(json_object['pdf_title']) == 1:
                            rows = df_final[(df_final['primary source pdf'] == json_object['pdf_title'][0]) &
                                            (df_final['date_start'] == json_object['nodes']['campaign'][0][
                                                'date_start'])]

                            for vulnerability in rows['vulnerability']:
                                vuln = vulnerability.lower()
                                if vuln.startswith('cve'):
                                    json_object['nodes']['vulnerability'].append({'name': vuln, 'id': vuln})

                # fill the ground truth.
                fill_ground_truth()

                # change the ids.
                Preprocessor.change_id(json_object)

                # create the relations
                json_object["relations"] = {"attributed_to": [], "targets": [], "employs": []}
                Preprocessor.relations_creation(json_object, "campaign", "APT", "attributed_to")
                Preprocessor.relations_creation(json_object, "campaign", "vulnerability", "targets")
                Preprocessor.relations_creation(json_object, "campaign", "attack_vector", "employs")

                with open(f'../../datasets/campaign_graph/{file}', 'w', encoding='utf-8') as json_file1:
                    json.dump(json_object, json_file1, ensure_ascii=False, indent=4)

    @staticmethod
    def modify_dates(json_object):
        json_object['nodes']['campaign'][0]['date_start'] = list(set(json_object['nodes']['campaign'][0]['date_start']))
        for i, date in enumerate(json_object['nodes']['campaign'][0]['date_start']):
            date_split = date.split('-')
            if len(date_split) > 2:
                date = '-'.join(date_split[:2])
                json_object['nodes']['campaign'][0]['date_start'][i] = date

    @staticmethod
    def preprocess_json_campaign_graph(path):
        df_aliases = pd.read_excel('/Users/manu/PycharmProjects/LlmTI/neo4j_db/raw_data/Aliases1.xlsx')

        for file in os.listdir(path):
            with open(f'{path}/{file}', 'rb') as json_file:
                print(f"File: {file}")
                json_object = json.load(json_file)

                def flatten_list(lst):
                    return [item for sublist in lst for item in
                            (flatten_list(sublist) if isinstance(sublist, list) else [sublist])]

                if len(json_object['nodes']['campaign']) > 0:
                    json_object['nodes']['campaign'][0]['actor'] = [json_object['nodes']['campaign'][0]['actor']]
                    json_object['nodes']['campaign'][0]['actor'] = flatten_list(
                        json_object['nodes']['campaign'][0]['actor'])

                if len(json_object['nodes']['APT']) > 0:
                    json_object['nodes']['APT'][0]['name'] = [json_object['nodes']['APT'][0]['name']]
                    json_object['nodes']['APT'][0]['name'] = flatten_list(json_object['nodes']['APT'][0]['name'])

                # Now we look for the aliases: for both the campaign and the APT we find all the aliases.
                # Then, we unify the two lists and assign the same to the campaign and to the APT.
                list_actor = []
                if len(json_object['nodes']['campaign']) > 0:
                    for actor in json_object['nodes']['campaign'][0]['actor']:
                        official_actor_campaign = df_aliases[df_aliases['alias'].str.lower() == actor.lower()]['name']
                        if not official_actor_campaign.empty:
                            official_name = official_actor_campaign
                            list_actor.extend(list(official_name))

                json_object['nodes']['campaign'][0]['actor'].extend(list_actor)

                list_name = []
                if len(json_object['nodes']['APT']) > 0:
                    for name in json_object['nodes']['APT'][0]['name']:
                        official_name_APT = df_aliases[df_aliases['alias'].str.lower() == name.lower()]['name']
                        if not official_name_APT.empty:
                            official_name = official_name_APT
                            list_name.extend(list(official_name))

                json_object['nodes']['APT'][0]['name'].extend(list_name)

                # union of the two lists.
                json_object['nodes']['APT'][0]['name'].extend(json_object['nodes']['campaign'][0]['actor'])
                json_object['nodes']['campaign'][0]['actor'].extend(json_object['nodes']['APT'][0]['name'])

                # delete the duplicates.
                json_object['nodes']['campaign'][0]['actor'] = list(set(json_object['nodes']['campaign'][0]['actor']))
                json_object['nodes']['APT'][0]['name'] = list(set(json_object['nodes']['APT'][0]['name']))

                # change id of the entities in the json file
                Preprocessor.change_id(json_object)
                Preprocessor.modify_dates(json_object)

                if "vulnerability" not in json_object['nodes']:
                    json_object['nodes']['vulnerability'] = []

                if 'attack_vector' not in json_object['nodes']:
                    json_object['nodes']['attack_vector'] = []

                # create the relations in the json file
                json_object["relations"] = {"attributed_to": [], "targets": [], "employs": []}
                Preprocessor.relations_creation(json_object, "campaign", "APT", "attributed_to")
                Preprocessor.relations_creation(json_object, "campaign", "vulnerability", "targets")
                Preprocessor.relations_creation(json_object, "campaign", "attack_vector", "employs")

                print("Final json object: ", json_object)

                with open(f'{path}/{file}', 'w') as json_file1:
                    json.dump(json_object, json_file1, indent=4)

    @staticmethod
    def data_analysis_json_mini_graph(path):
        for file in os.listdir(path):
            with open(f'{path}{file}', 'rb') as json_file:
                json_object = json.load(json_file)

                print("Campaign actor name: ", json_object['nodes']['campaign'][0]['actor'])
                print("APT name: ", json_object['nodes']['APT'][0]['name'])
                print("Dates: ", json_object['nodes']['campaign'][0]['date_start'])

                print("\n")

    @staticmethod
    def fill_similarities(dict_data, json_object_truth, json_object_results, check_type, check_type2, category,
                          sim_type):
        if (json_object_results[check_type][category] and isinstance(
                json_object_results[check_type][category], dict) and
                len(json_object_truth[check_type2][category]) > 0):

            print("Similarities: ", json_object_results[check_type][category])

            elements = [round(json_object_results[check_type][category][sim][1], 2) for sim in
                        json_object_results[check_type][category].keys() if
                        sim.startswith(category) and json_object_results[check_type][category][sim]]

            print("Elements: ", elements)

            dict_data[sim_type].append(elements)
        else:
            print("Ciao")
            dict_data[sim_type].append('NaN')

    @staticmethod
    def fill_fp_nodes(dict_data, json_object_results, check_type, category, fp_type):
        print(json_object_results[check_type][category])

        if category in json_object_results[check_type] and isinstance(
                json_object_results[check_type][category], dict):
            if 'false positives' in json_object_results[check_type][category]:
                fp = len(json_object_results[check_type][category]['false positives'])
            else:
                fp = 0
        else:
            fp = 0

        dict_data[fp_type].append(fp)

    @staticmethod
    def fill_positives(dict_data, json_object_truth, check_type, category, p_type):
        if category in json_object_truth[check_type]:
            dict_data[p_type].append(len(json_object_truth[check_type][category]))
        else:
            dict_data[p_type].append(0)

    @staticmethod
    def build_csv_from_json_similarities(path_dataset, path_graphs, path_saving, campaign_context):
        """
        :param path: this is the path where the results are stored.
        :param path1: this is the path of the dataset.
        :return:
        """

        keys_campaign_nodes = ["campaign", "APT", "attack_vector", "vulnerability"]
        keys_campaign_relations = ["attributed_to", "targets", "employs"]

        keys_context_nodes = ["APT", "country", "attack_vector", "vulnerability"]
        keys_context_relations = ["origin", "targets", "uses"]

        dict_cat_campaign = {"nodes": {key: [f"sim_{key}", f"fp_not_paired_{key}", f"p_{key}"]
                                       for key in keys_campaign_nodes},
                             "relations": {key: [f"sim_{key}", f"fp_not_paired_{key}", f"p_{key}"]
                                           for key in keys_campaign_relations}}

        dict_cat_context = {"nodes": {key: [f"sim_{key}", f"fp_not_paired_{key}", f"p_{key}"]
                                      for key in keys_context_nodes},
                            "relations": {key: [f"sim_{key}", f"fp_not_paired_{key}", f"p_{key}"]
                                          for key in keys_context_relations}}

        dict_cat = dict_cat_campaign if campaign_context == "campaign" else dict_cat_context

        dict_data = {"json": [], "title": []}
        temporary_dict = {element: [] for key in dict_cat.keys() for key2 in dict_cat[key].keys() for element in
                          dict_cat[key][key2]}
        dict_data.update(temporary_dict)

        for file in sorted(os.listdir(path_graphs)):
            with open(f'{path_graphs}/{file}', 'rb') as json_file_results:
                json_object_results = json.load(json_file_results)
                print("File: ", file)
                with open(f'{path_dataset}/{file}', 'rb') as json_file_truth:
                    json_object_truth = json.load(json_file_truth)

                    dict_data['json'].append(file)

                    if 'pdf_title' in json_object_truth:
                        dict_data['title'].append(json_object_truth['pdf_title'][0])
                    else:
                        dict_data['title'].append(json_object_truth['nodes']['APT'][0]['name'])

                    # Fill in for the nodes.
                    for key in dict_cat["nodes"].keys():
                        Preprocessor.fill_similarities(dict_data, json_object_truth, json_object_results,
                                                       'nodes_similarities', 'nodes',
                                                       key, dict_cat["nodes"][key][0])
                        Preprocessor.fill_fp_nodes(dict_data, json_object_results, 'nodes_similarities',
                                                   key, dict_cat["nodes"][key][1])
                        Preprocessor.fill_positives(dict_data, json_object_truth, "nodes", key,
                                                    dict_cat["nodes"][key][2])

                    for key in dict_cat["relations"].keys():
                        Preprocessor.fill_similarities(dict_data, json_object_truth, json_object_results,
                                                       'relations_similarities',
                                                       'relations', key, dict_cat["relations"][key][0])
                        Preprocessor.fill_fp_nodes(dict_data, json_object_results, 'relations_similarities',
                                                   key, dict_cat["relations"][key][1])
                        Preprocessor.fill_positives(dict_data, json_object_truth, "relations",
                                                    key, dict_cat["relations"][key][2])

        df_data = pd.DataFrame(dict_data)
        df_data.to_excel(f'{path_saving}')


if __name__ == '__main__':
    prep = Preprocessor()
    prep.preprocess_ground_truth()
