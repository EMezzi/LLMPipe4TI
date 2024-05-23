import pandas as pd
from transformers import RobertaModel, RobertaTokenizer, AutoModel, AutoTokenizer, AutoModelForSequenceClassification
import torch
from sklearn.metrics.pairwise import cosine_similarity

from neo4j_db.scripts.neo4j_controller import Neo4j_Controller
from neo4j_db.scripts.credentials import uri, user, password

from sentence_transformers import SentenceTransformer, util


def sim_func(string1, string2, path_model):
    tokenizer = AutoTokenizer.from_pretrained(path_model)
    model = AutoModel.from_pretrained(path_model)

    inputs1 = tokenizer(string1, return_tensors="pt", padding=True, truncation=True)
    inputs2 = tokenizer(string2, return_tensors="pt", padding=True, truncation=True)

    with torch.no_grad():
        outputs1 = model(**inputs1)
        outputs2 = model(**inputs2)

    # Extract the last hidden states (CLS tokens)
    embeddings1 = outputs1.last_hidden_state[:, 0, :]
    embeddings2 = outputs2.last_hidden_state[:, 0, :]

    # Calculate cosine similarity
    similarity = cosine_similarity(embeddings1, embeddings2)

    print("Cosine Similarity:", similarity.item())


def model_for_industrial_sector(contr):
    industrial_sectors = []
    result = contr.get_identities()

    for record in result:
        for key in record.keys():
            for key1 in record[key].keys():
                industrial_sectors.append(record[key][key1])

    t = []
    for industrial_sector in industrial_sectors:
        for industrial_sector1 in industrial_sectors:
            if industrial_sector != industrial_sector1:
                t.append((industrial_sector, industrial_sector1))

    return t


if __name__ == '__main__':
    pass