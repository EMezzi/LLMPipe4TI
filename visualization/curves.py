import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from results.scripts.metrics_calculation import MetricsCalculator
from inferring.scripts.variables import grid_search
from sklearn.metrics import PrecisionRecallDisplay, precision_recall_curve
import ast


def best_threshold(type):
    mc = MetricsCalculator()

    choice = 'campaign'
    thresholds = np.linspace(0, 1)

    for threshold_tp in thresholds:
        list_d = []
        mc.main_metrics(
            f'/Users/manu/PycharmProjects/LlmTI/results/campaign_graph/metrics/validation/results_{0}_{3}.xlsx',
            list_d, choice, threshold_tp, 0.00, 0, 3)
        pr = list_d[0][(0, 3, threshold_tp)][type]['pr']
        rec = list_d[0][(0, 3, threshold_tp)][type]['rec']
        f1 = list_d[0][(0, 3, threshold_tp)][type]['f1']

        plt.xlim(0, 1)
        plt.ylim(0, 1)
        plt.scatter(rec, pr)

    plt.show()

    # print(f"Threshold: {threshold_tp}, Threshold fp: {1.00}, Precision: {pr}, Recall: {rec}, F1-score: {f1}")


def func(sim_type, results_validation):
    results_validation[sim_type] = results_validation[sim_type].apply(lambda x: ast.literal_eval(x) if pd.notna(x) else x)
    validation = results_validation[sim_type].dropna(axis=0)

    y_true = [1 for l in validation for el in l]
    y_score = [el for l in validation for el in l]

    precision, recall, thresholds = precision_recall_curve(y_true, y_score)

    print(recall)
    print(precision)
    print(thresholds)

    plt.xlim(0, 1)
    plt.ylim(0, 1)
    plt.scatter(recall, precision)
    plt.show()


def precision_rec():
    mc = MetricsCalculator()

    results_validation = pd.read_excel(f'../results/campaign_graph/metrics/validation/results_{0}_{3}.xlsx')

    func('sim_vulnerability', results_validation)


if __name__ == '__main__':
    print("vulnerability")
    best_threshold('vulnerability')
    print("\n")

    print("vector")
    best_threshold('vector')
    print("\n")

    print("APT")
    best_threshold('APT')
    print("\n")
    print("campaign")
    best_threshold('campaign')
