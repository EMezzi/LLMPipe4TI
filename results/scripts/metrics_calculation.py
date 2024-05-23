import pandas as pd
import ast
import numpy as np
import matplotlib.pyplot as plt


class MetricsCalculator:
    @staticmethod
    def concatenate_lists(df, column):
        concatenated_list = []
        for item in df[column]:
            if isinstance(item, list):
                concatenated_list.extend(item)
            if isinstance(item, list) and len(item) == 0:
                concatenated_list.append(0)

        return concatenated_list

    @staticmethod
    def tp_calculation(threshold_tp, threshold_fp, df, column_p, column, column_tp):
        def count_elements_above_threshold(lst, threshold_tp, threshold_fp):
            if isinstance(lst, list):
                # Count elements greater than the threshold
                return sum(1 for x in lst if x >= threshold_tp)
            else:  # Check if lst is NaN
                return np.nan

        # df[column_tp] = df[column].apply(lambda x: count_elements_above_threshold(x, threshold_tp, threshold_fp))

        for index, row in df.iterrows():
            if isinstance(df.loc[index, column], list):
                df.loc[index, column_tp] = sum(1 for x in df.loc[index, column] if x >= threshold_tp)
            elif not isinstance(df.loc[index, column], list) and row[column_p] > 0:
                df.loc[index, column_tp] = 0
            elif not isinstance(df.loc[index, column], list) and row[column_p] == 0:
                df.loc[index, column_tp] = np.nan

    @staticmethod
    def fp_calculation(threshold_tp, threshold_fp, df, column, column_fp):
        def count_elements_below_threshold(lst, threshold_tp, threshold_fp):
            if isinstance(lst, list):
                return sum(1 for x in lst if x < threshold_tp)
            else:
                return 0

        df[column_fp] = df[column].apply(lambda x: count_elements_below_threshold(x, threshold_tp, threshold_fp))

    @staticmethod
    def fn_calculation(df, column_p, column_tp, column_fn):
        # mask = df[column_p] > 0
        # df[column_fn] = df[column_p].sub(df[column_tp]).where(mask, 0)
        for index, row in df.iterrows():
            if df.loc[index, column_p] >= 0 and df.loc[index, column_tp] >= 0:
                df.loc[index, column_fn] = df.loc[index, column_p] - df.loc[index, column_tp]
            else:
                df.loc[index, column_fn] = 0

    @staticmethod
    def precision(df, column_tp, column_fp, column_fp_threshold, column_pr):
        df[column_pr] = df[column_tp] / (df[column_fp] + df[column_fp_threshold] + df[column_tp])
        df[column_pr] = df[column_pr].replace(np.inf, 1)

    @staticmethod
    def recall(df, column_tp, column_fn, column_rec):
        df[column_rec] = df[column_tp] / (df[column_tp] + df[column_fn])
        df[column_rec] = df[column_rec].replace(np.inf, 1)

    @staticmethod
    def overall_metrics(df_data, category, threshold_tp, threshold_fp):
        MetricsCalculator.tp_calculation(threshold_tp, threshold_fp, df_data, f'p_{category}', f'sim_{category}', f'tp_{category}')
        MetricsCalculator.fp_calculation(threshold_tp, threshold_fp, df_data, f'sim_{category}',f'fp_{category}_threshold')
        MetricsCalculator.fn_calculation(df_data, f'p_{category}', f'tp_{category}', f'fn_{category}')
        MetricsCalculator.precision(df_data, f'tp_{category}', f'fp_not_paired_{category}', f'fp_{category}_threshold',
                                    f'pr_{category}')
        MetricsCalculator.recall(df_data, f'tp_{category}', f'fn_{category}', f'rec_{category}')

        pr = df_data[f'pr_{category}'].mean()
        rec = df_data[f'rec_{category}'].mean()
        f1 = 2 * ((pr * rec) / (pr + rec))

        return [round(pr, 2), round(rec, 2), round(f1, 2)]

    @staticmethod
    def similarities(df_data, sim_type):
        df_data[sim_type] = df_data[sim_type].apply(lambda x: ast.literal_eval if pd.notna(x) else x)

    @staticmethod
    def main_metrics(path, list_d, campaign_context, threshold_tp, threshold_fp, i=None, j=None):
        df_data = pd.read_excel(path, index_col=0)

        keys_campaign_nodes = ["campaign", "APT", "attack_vector", "vulnerability"]
        keys_campaign_relations = ["attributed_to", "employs", "targets"]

        keys_context_nodes = ["APT", "attack_vector", "vulnerability", "country"]
        keys_context_relations = ["origin", "uses", "targets"]

        keys_nodes, keys_relations = None, None

        if campaign_context == 'campaign':
            keys_nodes = keys_campaign_nodes
            keys_relations = keys_campaign_relations
        elif campaign_context == 'context':
            keys_nodes = keys_context_nodes
            keys_relations = keys_context_relations

        similarity_types = [f'sim_{key}' for key in keys_nodes]
        similarity_types.extend([f'sim_{key}' for key in keys_relations])

        for similarity_type in similarity_types:
            if similarity_type in df_data:
                df_data[similarity_type] = df_data[similarity_type].apply(
                    lambda x: ast.literal_eval(x) if pd.notna(x) else x)

        sim_dict = {'nodes': {f'sim_{key}': round(np.mean(MetricsCalculator.concatenate_lists(df_data, f'sim_{key}')), 2)
                              for key in keys_nodes if f'sim_{key}' in df_data},
                    'relations': {
                        f'sim_{key}': round(np.mean(MetricsCalculator.concatenate_lists(df_data, f'sim_{key}')), 2)
                        for key in keys_relations if f'sim_{key}' in df_data}}

        tot_sim = {'nodes': [], 'relations': []}
        for key in sim_dict.keys():
            for key2 in sim_dict[key].keys():
                tot_sim[key].append(sim_dict[key][key2])

        if campaign_context == 'campaign':
            camp_pr, camp_rec, camp_f1 = MetricsCalculator.overall_metrics(df_data, 'campaign', threshold_tp, threshold_fp)
            apt_pr, apt_rec, apt_f1 = MetricsCalculator.overall_metrics(df_data, 'APT', threshold_tp, threshold_fp)
            vector_pr, vector_rec, vector_f1 = MetricsCalculator.overall_metrics(df_data, 'attack_vector', threshold_tp, threshold_fp)
            vuln_pr, vuln_rec, vuln_f1 = MetricsCalculator.overall_metrics(df_data, 'vulnerability', threshold_tp, threshold_fp)
            attr_to_pr, attr_to_rec, attr_to_f1 = MetricsCalculator.overall_metrics(df_data, 'attributed_to', threshold_tp, threshold_fp)
            targets_pr, targets_rec, targets_f1 = MetricsCalculator.overall_metrics(df_data, 'targets', threshold_tp, threshold_fp)
            employs_pr, employs_rec, employs_f1 = MetricsCalculator.overall_metrics(df_data, 'employs', threshold_tp, threshold_fp)

            d = {(i, j, threshold_tp): {
                'campaign': {'pr': camp_pr, 'rec': camp_rec, 'f1': camp_f1, 'sim': sim_dict['nodes']['sim_campaign']},
                'APT': {'pr': apt_pr, 'rec': apt_rec, 'f1': apt_f1, 'sim': sim_dict['nodes']['sim_APT']},
                'vulnerability': {'pr': vuln_pr, 'rec': vuln_rec, 'f1': vuln_f1,
                                  'sim': sim_dict['nodes']['sim_vulnerability']},
                'vector': {'pr': vector_pr, 'rec': vector_rec, 'f1': vector_f1,
                           'sim': sim_dict['nodes']['sim_attack_vector']},
                'attr_to': {'pr': attr_to_pr, 'rec': attr_to_rec, 'f1': attr_to_f1,
                            'sim': sim_dict['relations']['sim_attributed_to']},
                'targets': {'pr': targets_pr, 'rec': targets_rec, 'f1': targets_f1,
                            'sim': sim_dict['relations']['sim_targets']},
                'employs': {'pr': employs_pr, 'rec': employs_rec, 'f1': employs_f1,
                            'sim': sim_dict['relations']['sim_employs']}}}

            list_d.append(d)

        elif campaign_context == 'context':
            apt_pr, apt_rec, apt_f1 = MetricsCalculator.overall_metrics(df_data, 'APT', 0.8, 0.00)
            country_pr, country_rec, country_f1 = MetricsCalculator.overall_metrics(df_data, 'country', 0.8, 0.00)
            vector_pr, vector_rec, vector_f1 = MetricsCalculator.overall_metrics(df_data, 'attack_vector', 0.8, 0.00)
            vuln_pr, vuln_rec, vuln_f1 = MetricsCalculator.overall_metrics(df_data, 'vulnerability', 0.8, 0.00)

            origin_pr, origin_rec, origin_f1 = MetricsCalculator.overall_metrics(df_data, 'origin', 0.8, 0.00)
            targets_pr, targets_rec, targets_f1 = MetricsCalculator.overall_metrics(df_data, 'targets', 0.8, 0.00)
            uses_pr, uses_rec, uses_f1 = MetricsCalculator.overall_metrics(df_data, 'uses', 0.8, 0.00)

            d = {(i, j): {
                'APT': {'pr': apt_pr, 'rec': apt_rec, 'f1': apt_f1, 'sim': sim_dict['nodes']['sim_APT']},
                'country': {'pr': country_pr, 'rec': country_rec, 'f1': country_f1,
                            'sim': sim_dict['nodes']['sim_country']},
                'vulnerability': {'pr': vuln_pr, 'rec': vuln_rec, 'f1': vuln_f1,
                                  'sim': sim_dict['nodes']['sim_vulnerability']},
                'vector': {'pr': vector_pr, 'rec': vector_rec, 'f1': vector_f1,
                           'sim': sim_dict['nodes']['sim_attack_vector']},
                'origin': {'pr': origin_pr, 'rec': origin_rec, 'f1': origin_f1,
                           'sim': sim_dict['relations']['sim_origin']},
                'uses': {'pr': uses_pr, 'rec': uses_rec, 'f1': uses_f1, 'sim': sim_dict['relations']['sim_uses']},
                'targets': {'pr': targets_pr, 'rec': targets_rec, 'f1': targets_f1,
                            'sim': sim_dict['relations']['sim_targets']}}}

            list_d.append(d)
