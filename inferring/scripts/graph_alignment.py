import os
import re
import json

import pandas as pd
import torch
from transformers import RobertaModel, AutoTokenizer, AutoModel
from sklearn.metrics.pairwise import cosine_similarity
import shutil

from sentence_transformers import SentenceTransformer, util


# model = SentenceTransformer("all-MiniLM-L6-v2")

# tokenizer = AutoTokenizer.from_pretrained("jackaduma/SecRoBERTa")
# model = AutoModel.from_pretrained("jackaduma/SecRoBERTa")


class GraphAligner:
    def __init__(self):
        self.tokenizer = AutoTokenizer.from_pretrained("jackaduma/SecRoBERTa")
        self.model = AutoModel.from_pretrained("jackaduma/SecRoBERTa")
        self.dict_node_comparison = {"campaign": self.campaign_comparison, "APT": self.apt_comparison,
                                     "vulnerability": GraphAligner.vulnerability_comparison,
                                     "country": self.country_comparison,
                                     "targeted_sector": self.targeted_sector_comparison,
                                     "attack_vector": self.attack_vector_comparison,
                                     "tool": self.tool_comparison, "malware": self.malware_comparison}

    @staticmethod
    def get_json_files(path_ground_truth, path_inferred):
        with open(path_ground_truth, 'rb') as json_ground_truth:
            file_truth = json.load(json_ground_truth)

        with open(path_inferred, 'rb') as json_inferred:
            file_inferred = json.load(json_inferred)

        return file_truth, file_inferred

    def similarity_names_apt_campaign(self, node_truth, node_infer):
        inputs1 = self.tokenizer(node_truth.lower(), return_tensors="pt", padding=True, truncation=True)
        inputs2 = []
        for name_infer in node_infer:
            inputs2.append(self.tokenizer(name_infer.lower(), return_tensors="pt", padding=True, truncation=True))

        with torch.no_grad():
            outputs1 = self.model(**inputs1)
            outputs2 = []

            for input2 in inputs2:
                outputs2.append(self.model(**input2))

        # Extract the last hidden states (CLS tokens)
        embeddings1 = outputs1.last_hidden_state[:, 0, :]
        embeddings2 = []

        for output2 in outputs2:
            embeddings2.append(output2.last_hidden_state[:, 0, :])

        apt_similarities = []
        for embedding2 in embeddings2:
            apt_similarities.append(cosine_similarity(embeddings1, embedding2)[0, 0].item())

        print("The similarities are: ", apt_similarities)
        apt_similarity = max(apt_similarities)
        print("The maximum similarity is: ", apt_similarity)

        return apt_similarity

    def campaign_comparison(self, node_truth, node_infer):
        """Campaign comparison with levenshtein distance and exact date matching"""

        print("\nCampaign similarity")

        if 'actor' in node_infer:
            actor_sim = self.similarity_names_apt_campaign(node_truth['actor'], node_infer['actor'])
            print(
                f"Node truth: {node_truth['actor'].lower()}, Node infer: {[x.lower() for x in node_infer['actor']]}. Similarity: {actor_sim}")
        else:
            actor_sim = 0

        if 'date_start' in node_infer:
            date_sim = 1 if any(node_truth['date_start'][:4] in x[:4] for x in node_infer['date_start']) else 0
            print(
                f"Node truth: {node_truth['date_start']}. Node infer: {node_infer['date_start']}. Similarity: {date_sim}")
        else:
            date_sim = 0

        ca_similarity = (actor_sim + date_sim) / 2
        print("Campaign similarity: ", ca_similarity)

        return ca_similarity

    def comparison_name(self, node_infer, node_truth):

        node_infer = re.sub(r'-', r' ', node_infer)
        node_truth = re.sub(r'-', r' ', node_truth)

        inputs1 = self.tokenizer(node_truth.lower(), return_tensors="pt", padding=True, truncation=True)
        inputs2 = self.tokenizer(node_infer.lower(), return_tensors="pt", padding=True, truncation=True)

        with torch.no_grad():
            outputs1 = self.model(**inputs1)
            outputs2 = self.model(**inputs2)

        embeddings1 = outputs1.last_hidden_state[:, 0, :]
        embeddings2 = outputs2.last_hidden_state[:, 0, :]

        similarity = cosine_similarity(embeddings1, embeddings2)[0, 0].item()

        return similarity

    def apt_comparison(self, node_truth, node_infer):
        """String similarity with cosine similarity"""

        print("\nAPT similarity")
        apt_similarity = 0
        name_similarity = self.similarity_names_apt_campaign(node_truth['name'], node_infer['name'])

        apt_similarity += name_similarity

        if "description" in node_infer and "goals" in node_infer and "type" in node_infer:
            description_similarity = self.comparison_name(node_truth['description'], node_infer['description'])
            goals_similarity = self.comparison_name(node_truth['goals'], node_infer['goals'])
            type_similarity = self.comparison_name(node_truth['labels'], node_infer['type'])

            apt_similarity += description_similarity
            apt_similarity += goals_similarity
            apt_similarity += type_similarity

            apt_similarity /= 4

        print(f"""Node truth name: {node_truth['name']}. Node infer name: {[x.lower() for x in node_infer['name']]}. 
                APT Similarity: {apt_similarity}""")

        return apt_similarity

    @staticmethod
    def vulnerability_comparison(node_truth, node_infer):
        """Exact comparison"""

        print("\nVulnerability similarity")

        vu_similarity = 1 if node_truth['name'].lower() == node_infer['name'].lower() else 0
        print(
            f"Node truth name: {node_truth['name']}. Node infer name: {node_infer['name']}. Vulnerability similarity: {vu_similarity}")

        return vu_similarity

    def attack_vector_comparison(self, node_truth, node_infer):
        """Technique comparison with levenshtein distance"""

        print("\nTechnique similarity")

        name_truth, name_infer = node_truth['name'].lower(), node_infer['name'].lower()
        name_truth, name_infer = re.sub(r'-', r'', name_truth), re.sub(r'-', r'', name_infer)

        print(f"Name truth: {name_truth}. Name infer: {name_infer}")
        print(f"Name truth split: {name_truth.split()}, {len(name_truth.split())}. Name infer split: {name_infer.split()}, {len(name_infer.split())}")

        inputs1 = self.tokenizer(name_truth, return_tensors="pt", padding=True, truncation=True)
        inputs2 = []

        name_truth_split = name_truth.split()
        name_infer_split = name_infer.split()

        print("Inputs2")
        for i in range(len(name_infer_split)):
            print('Ueue: ', ' '.join(name_infer_split[i:i + len(name_truth_split)]))
            inputs2.append(
                self.tokenizer(' '.join(name_infer_split[i:i + len(name_truth_split)]), return_tensors='pt', padding=True,
                               truncation=True))

        print("Inputs2: ", inputs2)

        with torch.no_grad():
            outputs1 = self.model(**inputs1)
            outputs2 = []
            for input2 in inputs2:
                outputs2.append(self.model(**input2))

        # Extract the last hidden states (CLS tokens)
        embeddings1 = outputs1.last_hidden_state[:, 0, :]
        embeddings2 = []
        for output2 in outputs2:
            embeddings2.append(output2.last_hidden_state[:, 0, :])

        # Calculate cosine similarity
        attack_vector_similarities = [cosine_similarity(embeddings1, embedding2)[0, 0].item() for embedding2 in
                                      embeddings2]

        print("All the similarities: ", attack_vector_similarities)

        attack_vector_similarity = max(attack_vector_similarities) if attack_vector_similarities else 0

        print(f"Technique similarity: {attack_vector_similarity}")

        return attack_vector_similarity

    def country_comparison(self, node_truth, node_infer):
        print("\nCountry similarity")

        country_similarity = self.comparison_name(node_infer['name'], node_truth['name'])

        print(f"""Node truth name: {node_truth['name']}. Node infer name: {node_infer['name']}. 
        Sector similarity: {country_similarity}""")

        return country_similarity

    def targeted_sector_comparison(self, node_truth, node_infer):
        print("\nSector similarity")

        targeted_sector_similarity = self.comparison_name(node_infer['name'], node_truth['name'])

        print(f"Node truth name: {node_truth['name']}. Node infer name: {node_infer['name']}. "
              f"Sector similarity: {targeted_sector_similarity}")

        return targeted_sector_similarity

    def tool_comparison(self, node_truth, node_infer):
        print("\nTool similarity")

        tool_similarity = self.comparison_name(node_infer['name'], node_truth['name'])

        print(f"Node truth name: {node_truth['name']}. Node infer name: {node_infer['name']}. "
              f"Tool similarity: {tool_similarity}")

        return tool_similarity

    def malware_comparison(self, node_truth, node_infer):
        print("\nMalware similarity")

        malware_similarity = self.comparison_name(node_infer['name'], node_truth['name'])

        print(f"Node truth name: {node_truth['name']}. Node infer name: {node_infer['name']}. "
              f"Malware similarity: {malware_similarity}")

        return malware_similarity

    @staticmethod
    def nodes_extraction(nodes, category_nodes):
        """
        :param nodes: nodes of the graph.
        :param category_nodes: category of the nodes.
        :return: nodes from the json file.
        """

        nodes = {node["id"]: node for node in nodes[category_nodes]} if category_nodes in nodes else {}
        return nodes

    @staticmethod
    def relations_extraction(relations, category_relations):
        """
        :param relations: relations of the graph.
        :param category_relations: category of the relations to extract.
        :return: relations from the json file.
        """

        relations = {category_relations + str(i + 1): relation for i, relation in
                     enumerate(relations[category_relations])} if category_relations in relations else {}

        return relations

    def nodes_comparison_method(self, nodes_truth, nodes_infer, category_comparison):
        """
        Method to implement the comparison between nodes.
        :param nodes_truth: the nodes of the ground truth.
        :param nodes_infer: the nodes obtained through inferring.
        :param category_comparison: type of nodes to receive campaign, actor, vulnerability or technique.
        :return:
        """

        dict_sim = {}
        paired = []

        if not nodes_truth and not nodes_infer:
            dict_sim = "No ground truth and no false positives"
        elif not nodes_truth and nodes_infer:
            dict_sim = {"false positives": nodes_infer}
        elif nodes_truth and nodes_infer:
            for key_truth in nodes_truth.keys():
                dict_sim[key_truth] = []
                for key_infer in nodes_infer.keys():
                    if key_infer not in paired:
                        value = self.dict_node_comparison[category_comparison](nodes_truth[key_truth],
                                                                               nodes_infer[key_infer])
                        if value > 0:
                            dict_sim[key_truth].append((key_infer, value))

                if dict_sim[key_truth]:
                    maximum = max(dict_sim[key_truth], key=lambda x: x[1])
                    paired.append(maximum[0])
                    dict_sim[key_truth] = maximum

            total_sim = sum(dict_sim[key][1] if dict_sim[key] else 0 for key in dict_sim.keys()) / len(dict_sim)

            dict_sim["false positives"] = {key: value for key, value in nodes_infer.items() if key not in paired}
            dict_sim["total_sim"] = total_sim

        return dict_sim

    def relations_comparison_method(self, relations_truth, relations_infer, nodes_truth, nodes_infer):
        dict_sim = {}
        paired = []

        if not relations_truth and not relations_infer:
            dict_sim = "No relations to pair and no false positives"
            return dict_sim
        elif not relations_truth and relations_infer:
            dict_sim = {"false positives": relations_infer}
            return dict_sim
        else:
            for key_truth in relations_truth.keys():
                dict_sim[key_truth] = []
                try:
                    first_node_truth = nodes_truth[relations_truth[key_truth][0][:-1]][relations_truth[key_truth][0]]
                    second_node_truth = nodes_truth[relations_truth[key_truth][1][:-1]][relations_truth[key_truth][1]]
                except Exception as e:
                    first_node_truth = nodes_truth[relations_truth[key_truth][0][:-1]][relations_truth[key_truth][0]]
                    second_node_truth = nodes_truth[relations_truth[key_truth][1][:-2]][relations_truth[key_truth][1]]

                for key_infer in relations_infer.keys():
                    if relations_infer[key_infer] not in paired:

                        if relations_infer[key_infer][0] in nodes_infer[relations_infer[key_truth][0][:-1]] and \
                                relations_infer[key_infer][1] in nodes_infer[relations_infer[key_truth][1][:-1]]:
                            first_node_infer = nodes_infer[relations_infer[key_truth][0][:-1]][
                                relations_infer[key_infer][0]]
                            second_node_infer = nodes_infer[relations_infer[key_truth][1][:-1]][
                                relations_infer[key_infer][1]]

                            value_first_node = self.dict_node_comparison[first_node_truth["id"][:-1]](first_node_truth,
                                                                                                      first_node_infer)
                            value_second_node = self.dict_node_comparison[second_node_truth["id"][:-1]](
                                second_node_truth,
                                second_node_infer)

                            rel_sim = (value_first_node + value_second_node) / 2
                            dict_sim[key_truth].append(((first_node_infer["id"], second_node_infer["id"]), rel_sim))

                if dict_sim[key_truth]:
                    maximum = max(dict_sim[key_truth], key=lambda x: x[1])
                    dict_sim[key_truth] = maximum
                    paired.append(list(maximum[0]))

            total_sim = sum(dict_sim[key][1] if dict_sim[key] else 0 for key in dict_sim.keys()) / len(dict_sim)
            dict_sim["false positives"] = {key: value for key, value in relations_infer.items() if value not in paired}
            dict_sim["total_sim"] = total_sim

        return dict_sim

    def nodes_comparison(self, nodes_truth, nodes_inferred):
        keys = nodes_truth.keys()
        dict_nodes_truth, dict_nodes_infer = {}, {}
        for key in keys:
            dict_nodes_truth[key] = GraphAligner.nodes_extraction(nodes_truth, key)
            dict_nodes_infer[key] = GraphAligner.nodes_extraction(nodes_inferred, key)

        dict_sim = {}
        for key in dict_nodes_truth.keys():
            dict_sim[key] = self.nodes_comparison_method(dict_nodes_truth[key], dict_nodes_infer[key], key)

        print("\n")
        for key in dict_sim.keys():
            print(f"{key.upper()} nodes similarity: {dict_sim[key]}")
        print("\n")

        return dict_sim, dict_nodes_truth, dict_nodes_infer

    def relations_comparison(self, edges_truth, edges_infer, nodes_truth, nodes_infer):
        keys = edges_truth.keys()

        dict_relations_truth, dict_relations_infer = {}, {}
        for key in keys:
            dict_relations_truth[key] = GraphAligner.relations_extraction(edges_truth, key)
            dict_relations_infer[key] = GraphAligner.relations_extraction(edges_infer, key)

        dict_sim = {}
        for key in dict_relations_truth.keys():
            dict_sim[key] = self.relations_comparison_method(dict_relations_truth[key], dict_relations_infer[key],
                                                             nodes_truth,
                                                             nodes_infer)

        return dict_sim

    def comparison(self, file_infer, file_truth, file_inferred, path_saving):
        # Extract the nodes and relations for the ground truth and the inferred nodes.
        nodes_truth, nodes_inferred = file_truth["nodes"], file_inferred["nodes"]
        relations_truth, relations_inferred = file_truth["relations"], file_inferred["relations"]

        # Gather the results of the comparison
        nodes_dict_sim, nodes_dict_truth, nodes_dict_infer = self.nodes_comparison(nodes_truth, nodes_inferred)
        relations_dict_sim = self.relations_comparison(relations_truth, relations_inferred, nodes_dict_truth,
                                                       nodes_dict_infer)

        json_object = {"nodes_similarities": nodes_dict_sim, "relations_similarities": relations_dict_sim}

        with open(f"{path_saving}/{file_infer}", "w", encoding="utf-8") as json_file:
            json.dump(json_object, json_file, indent=4)

    def main_graph_alignment(self, path_dataset, path_graphs, path_saving):
        if os.path.exists(path_saving):
            answer = input(f"Sure you want to delete the directory? {path_saving}")
            if answer == 'yes':
                shutil.rmtree(path_saving)
                os.makedirs(path_saving)
        else:
            os.makedirs(path_saving)

        for i, file_infer in enumerate(sorted(os.listdir(path_graphs))):
            print(i, file_infer)
            file_truth, file_inferred = GraphAligner.get_json_files(f'{path_dataset}/{file_infer}',
                                                                    f'{path_graphs}/{file_infer}')

            self.comparison(file_infer, file_truth, file_inferred, path_saving)
