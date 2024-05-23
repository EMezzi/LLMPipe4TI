import pandas as pd
import ast
import numpy as np
import matplotlib.pyplot as plt


class MetricsCalculator:
    def __init__(self, path):
        self.df = pd.read_excel(path)
        self.tp, self.fp, self.fn = 0, 0, 0
        self.prec, self.rec, self.f1 = 0, 0, 0

    def concatenate_lists(self, df, column):
        concatenated_list = []
        for item in self.df[column]:
            if isinstance(item, list):
                concatenated_list.extend(item)
            if isinstance(item, list) and len(item) == 0:
                concatenated_list.append(0)

        return concatenated_list

    def tp_calculation(self, threshold_tp, column, column_tp):
        def count_elements_above_threshold(lst, threshold_tp):
            if isinstance(lst, list):
                # Count elements greater than the threshold
                self.tp = sum(1 for x in lst if x >= threshold_tp)
            else:  # Check if lst is NaN
                self.tp = np.nan

        self.df[column_tp] = self.df[column].apply(lambda x: count_elements_above_threshold(x, threshold_tp))

    def fp_calculation(self, threshold_fp, threshold_tp, column, column_fp):
        def count_elements_below_threshold(lst, threshold_fp, threshold_tp):
            if isinstance(lst, list):
                self.fp = sum(1 for x in lst if threshold_fp <= x < threshold_tp)
            else:
                self.fp = np.nan

        self.df[column_fp] = self.df[column].apply(lambda x: count_elements_below_threshold(x, threshold_fp, threshold_tp))

    def fn_calculation(self, column_p, column_tp, column_fn):
        mask = self.df[column_p] > 0
        self.df[column_fn] = self.df[column_p].sub(self.df[column_tp]).where(mask, 0)

    def precision(self, column_tp, column_fp, column_fp_threshold, column_prec):
        self.df[column_prec] = self.df[column_tp] / (self.df[column_fp] + self.df[column_fp_threshold])
        self.df[column_prec] = self.df[column_prec].replace(np.inf, 1)

    def recall(self, column_tp, column_fn, column_rec):
        self.df[column_rec] = self.df[column_tp] / (self.df[column_tp] + self.df[column_fn])
        self.df[column_rec] = self.df[column_rec].replace(np.inf, 1)

    def f1_score(self):
        self.f1 = 2 * ((self.prec * self.rec))

    def overall_metrics(self, category, threshold_tp, threshold_fp):
        self.tp_calculation(threshold_tp, f'sim_{category}', f'tp_{category}')
        self.fp_calculation(threshold_fp, threshold_tp,f'sim_{category}', f'fp_{category}_threshold')
        self.fn_calculation(f'p_{category}', f'tp_{category}', f'fn_{category}')

        self.precision(f'tp_{category}', f'fp_not_paired_{category}', f'fp_{category}_threshold', f'{category}_prec')
        self.recall(f'tp_{category}', f'fn_{category}', f'rec_{category}')
        self.f1_score()

        self.prec = self.df[f'{category}_prec'].mean()
        self.rec = self.df[f'rec_{category}'].mean()
        self.f1 = 2 * ((self.prec * self.rec) / (self.prec + self.rec))



def main_metrics(path, i, j, d):
    df_data = pd.read_excel(path, index_col=0)

    df_data['sim_camp'] = df_data['sim_camp'].apply(ast.literal_eval)
    df_data['sim_APT'] = df_data['sim_APT'].apply(lambda x: ast.literal_eval(x) if pd.notna(x) else x)
    df_data['sim_vuln'] = df_data['sim_vuln'].apply(lambda x: ast.literal_eval(x) if pd.notna(x) else x)
    df_data['sim_vector'] = df_data['sim_vector'].apply(lambda x: ast.literal_eval(x) if pd.notna(x) else x)

    df_data['sim_attr_to'] = df_data['sim_attr_to'].apply(lambda x: ast.literal_eval(x) if pd.notna(x) else x)
    df_data['sim_targets'] = df_data['sim_targets'].apply(lambda x: ast.literal_eval(x) if pd.notna(x) else x)
    df_data['sim_employs'] = df_data['sim_employs'].apply(lambda x: ast.literal_eval(x) if pd.notna(x) else x)

    sim_camp = np.mean(concatenate_lists(df_data, 'sim_camp'))
    sim_apt = np.mean(concatenate_lists(df_data, 'sim_APT'))
    sim_vuln = np.mean(concatenate_lists(df_data, 'sim_vuln'))
    sim_vector = np.mean(concatenate_lists(df_data, 'sim_vector'))

    sim_attr_to = np.mean(concatenate_lists(df_data, 'sim_attr_to'))
    sim_targets = np.mean(concatenate_lists(df_data, 'sim_targets'))
    sim_employs = np.mean(concatenate_lists(df_data, 'sim_employs'))

    print("Similarity Campaign: ", sim_camp)
    print("Similarity APT: ", sim_apt)
    print("Similarity Vuln: ", sim_vuln)
    print("Similarity attack vector: ", sim_vector)
    tot_similarity_nodes = (sim_camp + sim_apt + sim_vuln + sim_vector) / 4
    print(f"Total similarity nodes: {tot_similarity_nodes}")
    print("\n")

    print("Similarity attr_to: ", sim_attr_to)
    print("Similarity targets: ", sim_targets)
    print("Similarity employs: ", sim_employs)
    tot_similarity_rel = (sim_attr_to + sim_targets + sim_employs) / 3
    print("Total similarity relations: ", tot_similarity_rel)
    print("\n\n")

    print("Calculation evaluation metrics")
    camp_prec, camp_rec, camp_f1 = overall_metrics(df_data, 'camp', 0.8, 0.5)
    apt_prec, apt_rec, apt_f1 = overall_metrics(df_data, 'APT', 0.8, 0.5)
    vuln_prec, vuln_rec, vuln_f1 = overall_metrics(df_data, 'vuln', 0.8, 0.5)
    vector_prec, vector_rec, vector_f1 = overall_metrics(df_data, 'vector', 0.3, 0.00)

    cat = ['camp', 'APT', 'vuln', 'vector']

    d[(i, j)] = {'camp': {'prec': camp_prec, 'rec': camp_rec, 'f1': camp_f1},
                 'apt': {'prec': apt_prec, 'rec': apt_rec, 'f1': apt_f1},
                 'vuln': {'prec': vuln_prec, 'rec': vuln_rec, 'f1': vuln_f1},
                 'vector': {'prec': vector_prec, 'rec': vector_rec, 'f1': vector_f1}}

    # df_data.to_excel(path)
