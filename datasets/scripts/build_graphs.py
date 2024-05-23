import os
import shutil

import pandas as pd
import json
import neo4j
import datetime

from neo4j_db.scripts.credentials import uri, user, password
from neo4j_db.scripts.neo4j_controller import Neo4j_Controller


def manage_directories():
    """
    :return:
    """

    """
    shutil.rmtree('dataset_json_graphs/campaign_graph/')
    os.makedirs('dataset_json_graphs/campaign_graph/')
    """

    shutil.rmtree('../context_graph/')
    os.makedirs('../context_graph/')


def relations_creation(nodes_relations, starting_key, ending_key, relation_name):
    for starting_node in nodes_relations["nodes"][starting_key]:
        for ending_node in nodes_relations["nodes"][ending_key]:
            nodes_relations["relations"][relation_name].append((starting_node["id"], ending_node["id"]))


def nodes_enumeration(nodes_relations):
    for key in nodes_relations["nodes"].keys():
        for i, el in enumerate(nodes_relations["nodes"][key]):
            nodes_relations["nodes"][key][i]["id"] = key + str(i + 1)


def json_object_generation(file_path, pdf_names, num_records, nodes_relations):
    json_object = {}

    if pdf_names and num_records:
        json_object = {"pdf_title": pdf_names, "num_records": num_records}

    json_object["nodes"] = nodes_relations["nodes"]
    json_object["relations"] = nodes_relations["relations"]

    with open(file_path, "w", encoding='utf-8') as json_file:
        json.dump(json_object, json_file, ensure_ascii=False, indent=4)


def transform_actor_context_json(file_path, result):
    nodes_key = ["APT", "country", "targeted_sector", "tool", "malware", "attack_vector"]
    nodes_relations = {
        "nodes": {"APT": [], "country": [], "targeted_sector": [], "tool": [], "malware": [], "attack_vector": []},
        "relations": {"alias": [], "origin": [], "targets": [], "targets1": [], "uses": [], "uses1": [], "uses2": []}}

    for record in result:
        for key in record.keys():
            d = {}
            if key in nodes_key:
                if record[key]:
                    for key1 in record[key].keys():
                        d[key1] = record[key][key1]
                    if d not in nodes_relations["nodes"][key]:
                        nodes_relations["nodes"][key].append(d)

    # Creation of the vulnerabilities in the dataset
    df_final = pd.read_excel(
        '/Users/manu/PycharmProjects/LlmTI/data_preprocessing/discard_pdfs/rel_threatactor_vulnerabilities_final.xlsx')
    vulnerability_attack = list(
        df_final[df_final["name"] == nodes_relations['nodes']['APT'][0]['name']]['vulnerability'].str.lower())
    vulnerability = [vuln for vuln in vulnerability_attack if vuln.startswith('cve')]
    nodes_relations['nodes']['vulnerability'] = [{'name': vuln, 'id': i + 1} for i, vuln in enumerate(vulnerability)]

    # Integrated attack vectors from the dataset
    attack = [att for att in vulnerability_attack if not att.startswith('cve') and att != 'unknown']

    for new_attack in attack:
        flag = 0
        for old_attack in nodes_relations["nodes"]["attack_vector"]:
            if new_attack == old_attack["name"]:
                flag = 1
                
        if flag == 0:
            nodes_relations['nodes']['attack_vector'].append({'name': new_attack})

    # Enumeration of the nodes
    nodes_enumeration(nodes_relations)

    """Creation of the relations"""
    relations_creation(nodes_relations, "APT", "country", "origin")
    relations_creation(nodes_relations, "APT", "targeted_sector", "targets")
    relations_creation(nodes_relations, "APT", "vulnerability", "targets1")
    relations_creation(nodes_relations, "APT", "tool", "uses")
    relations_creation(nodes_relations, "APT", "malware", "uses1")
    relations_creation(nodes_relations, "APT", "attack_vector", "employs")

    # Delete relation between APT and sector and create the one between APT and vulnerability
    del nodes_relations["relations"]["targets"]

    # Delete the useless nodes
    del nodes_relations["nodes"]["targeted_sector"]
    del nodes_relations["nodes"]["tool"]
    del nodes_relations["nodes"]["malware"]

    # Delete and rename relations
    del nodes_relations["relations"]["uses"]
    del nodes_relations["relations"]["uses1"]
    del nodes_relations["relations"]["alias"]
    nodes_relations['relations']['uses'] = nodes_relations['relations'].pop('uses2')
    nodes_relations['relations']['targets'] = nodes_relations['relations'].pop('targets1')

    json_object_generation(file_path, None, None, nodes_relations)


def date_transform(record, key, key1):
    date_object = record[key][key1]
    date = datetime.date(date_object.year, date_object.month, date_object.day)
    string_date = date.strftime("%Y-%m")
    return string_date


def transform_mini_graph_json(file_path, excel_df, result):
    nodes_key = ['campaign', 'APT', 'attack_vector', 'vulnerability']

    nodes_relations = {"nodes": {"campaign": [], "APT": [], "attack_vector": [], "vulnerability": []},
                       "relations": {"attributed_to": [], "targets": [], "employs": []}}

    for record in result:
        for key in record.keys():
            d = {}
            if key in nodes_key:
                if record[key]:
                    for key1 in record[key].keys():
                        if isinstance(record[key][key1], neo4j.time.Date):
                            d[key1] = date_transform(record, key, key1)
                        else:
                            d[key1] = record[key][key1]
                    if d not in nodes_relations["nodes"][key]:
                        nodes_relations["nodes"][key].append(d)

    # Enumerate the elements
    nodes_enumeration(nodes_relations)

    """Creation of the relations between campaigns and the other elements"""

    relations_creation(nodes_relations, "campaign", "APT", "attributed_to")  # Campaigns and actors
    relations_creation(nodes_relations, "campaign", "vulnerability", "targets")  # Campaigns and vulnerability
    relations_creation(nodes_relations, "campaign", "attack_vector", "employs")  # Campaigns and techniques

    pdf_names = list(excel_df[(excel_df['name'] == nodes_relations['nodes']['campaign'][0]['actor']) &
                              (excel_df['date_start'] == nodes_relations['nodes']['campaign'][0]['date_start'])][
                         'primary source pdf'].unique())

    json_object_generation(file_path, pdf_names, len(result), nodes_relations)

    return nodes_relations


if __name__ == '__main__':
    # Read the Excel file containing the campaigns
    # manage_directories()
    campaigns = pd.read_excel('../../data_preprocessing/discard_pdfs/rel_threatactor_vulnerabilities_final.xlsx')

    actor_start_date_pairs = [(actor, start_date) for actor, start_date in
                              zip(campaigns['name'], campaigns['date_start'])]
    actor_start_date_pairs = list(set(actor_start_date_pairs))

    controller = Neo4j_Controller(uri, user, password)

    actors = list(set([actor for actor in campaigns['name']]))
    print(actors)

    # For the context
    for i, actor in enumerate(sorted(actors)):
        print("Actor: ", actor)
        result_actor_context = controller.get_actor_context(actor)
        if result_actor_context:
            transform_actor_context_json(f'../context_graph/{i}.json', result_actor_context)

    """
    for i, pair in enumerate(sorted(actor_start_date_pairs)):
        print("Pair: ", i, pair[0], pair[1])
        result_mini_graph = controller.get_campaign(pair[0], pair[1])
        if result_mini_graph:
            campaign_graph = transform_mini_graph_json('dataset_json_graphs/campaign_graph/' + str(i) + '.json', campaigns,
                                                   result_mini_graph)
    """
