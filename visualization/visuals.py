import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from results.scripts.metrics_calculation import MetricsCalculator
from inferring.scripts.variables import grid_search
import math
import matplotlib.patches as mpatches


def maximum_x_maximum_y(points_uncertainty):
    def euclidean_distance(x1, y1, x2, y2):
        return math.sqrt((x2 - x1) ** 2 + (y2 - y1) ** 2)

    def midpoint(point1, point2):
        x_mid = (point1[0] + point2[0]) / 2
        y_mid = (point1[1] + point2[1]) / 2
        return (x_mid, y_mid)

    distances = []
    for point in points_uncertainty:
        for point1 in points_uncertainty:
            if point != point1:
                distances.append(
                    (euclidean_distance(point[0], point[1], point1[0], point1[1]), midpoint(point, point1)))

    print(distances)
    distances = sorted(distances, reverse=True, key=lambda x: x[0])
    print(distances)

    radius = distances[0][0]
    x_centre = distances[0][1][0]
    y_centre = distances[0][1][1]

    return radius, x_centre, y_centre


def plot(category, marker, points):
    ax.scatter([point[0] for point in points[category]][2:], [point[1] for point in points[category]][2:],
               s=200, c='white', edgecolors='black', marker=marker)
    ax.scatter([point[0] for point in points[category]][:2], [point[1] for point in points[category]][:2],
               s=500, c='white', edgecolors='black', label=category, marker=marker)


if __name__ == '__main__':
    mc = MetricsCalculator()

    # Graph for the validation
    m_l = []
    thresholds_tp = np.arange(0.80)
    for i, temperature in enumerate(grid_search['temperature']):
        for j, prompt in enumerate(grid_search['prompts']):
            mc.main_metrics(f'../results/campaign_graph/metrics/validation/results_{i}_{j}.xlsx', m_l,
                            'campaign', 0.80, 0.00, i, j)

    keys_cat = ['campaign', 'APT', 'vulnerability', 'vector']
    points = {'campaign': [], 'APT': [], 'vulnerability': [], 'vector': []}

    for key_cat in keys_cat:
        for result in m_l:
            for key in result.keys():
                points[key_cat].append((result[key][key_cat]['rec'], result[key][key_cat]['pr']))

    fig, ax = plt.subplots()

    ax.set_xlabel('Recall')
    ax.set_ylabel('Precision')

    print(points['campaign'])

    points['campaign'] = sorted(points['campaign'], key=lambda t: t[0] * t[1], reverse=True)
    points['APT'] = sorted(points['APT'], key=lambda t: t[0] * t[1], reverse=True)
    points['vulnerability'] = sorted(points['vulnerability'], key=lambda t: t[0] * t[1], reverse=True)
    points['vector'] = sorted(points['vector'], key=lambda t: t[0] * t[1], reverse=True)

    plot('vulnerability', 'h', points)
    plot('vector', 's', points)
    plot('APT', 'p', points)
    plot('campaign', 'o', points)

    ax.set(xlim=(0, 1), xticks=np.arange(0, 1.01), ylim=(0, 1), yticks=np.arange(0, 1.01))
    ax.legend(loc='upper left', labelspacing=1.5, handleheight=2.5, handlelength=1.5, borderpad=1.0)
    xticks = ax.xaxis.get_major_ticks()
    xticks[0].label1.set_visible(False)
    plt.savefig('validation_nodes.png')
    plt.show()

    """Uncertainty points and graphs"""

    points_uncertainty = {0: {'campaign': [], 'APT': [], 'vulnerability': [], 'vector': []},
                          1: {'campaign': [], 'APT': [], 'vulnerability': [], 'vector': []}}
    d_uncertainty = {}
    for i, temperature in enumerate(grid_search['temperature']):
        l_uncertainty = []
        for j in range(10):
            mc.main_metrics(f'../results/campaign_graph/metrics/test/results_{temperature}_3_{j}.xlsx', l_uncertainty,
                            'campaign', 0.80, 0.00)
        d_uncertainty[temperature] = l_uncertainty

    for temperature in [0, 1]:
        print("Temperature: ", temperature)
        for result in d_uncertainty[temperature]:
            print(result)
            for key_cat in keys_cat:
                for key in result.keys():
                    points_uncertainty[temperature][key_cat].append(
                        (result[key][key_cat]['rec'], result[key][key_cat]['pr']))

    fig, ax = plt.subplots()

    ax.set_xlabel('Recall')
    ax.set_ylabel('Precision')

    radius, x_centre, y_centre = maximum_x_maximum_y(points_uncertainty[0]['campaign'])
    circle1 = plt.Circle((x_centre, y_centre), radius, color='blue', alpha=0.7)
    radius, x_centre, y_centre = maximum_x_maximum_y(points_uncertainty[1]['campaign'])
    circle2 = plt.Circle((x_centre, y_centre), radius, color='blue', alpha=0.2)
    ax.add_patch(circle1)
    ax.add_patch(circle2)

    u_campaign = mpatches.Patch(color='blue', label='uncertainty campaign')

    ax.scatter([point[0] for point in points['campaign'][:1]], [point[1] for point in points['campaign'][:1]],
               s=500, c='white', edgecolors='black', marker="o")
    camp = ax.scatter([point[0] for point in points['campaign'][1:2]], [point[1] for point in points['campaign'][1:2]],
                      s=500, c='white', edgecolors='black', label='Campaign', marker="o")

    radius, x_centre, y_centre = maximum_x_maximum_y(points_uncertainty[0]['vulnerability'])
    circle1 = plt.Circle((x_centre, y_centre), radius, color='green', alpha=0.7)
    radius, x_centre, y_centre = maximum_x_maximum_y(points_uncertainty[1]['vulnerability'])
    circle2 = plt.Circle((x_centre, y_centre), radius, color='green', alpha=0.2)

    ax.add_patch(circle1)
    ax.add_patch(circle2)

    u_vuln = mpatches.Patch(color='green', label='uncertainty vulnerability')

    ax.scatter([point[0] for point in points['vulnerability'][:1]], [point[1] for point in points['vulnerability'][:1]],
               s=500, c='white', edgecolors='black', marker="h")
    vuln = ax.scatter([point[0] for point in points['vulnerability'][1:2]],
                      [point[1] for point in points['vulnerability'][1:2]],
                      s=500, c='white', edgecolors='black', label='vulnerability', marker="h")

    radius, x_centre, y_centre = maximum_x_maximum_y(points_uncertainty[0]['vector'])
    circle1 = plt.Circle((x_centre, y_centre), radius, color='red', alpha=0.7)
    radius, x_centre, y_centre = maximum_x_maximum_y(points_uncertainty[1]['vector'])
    circle2 = plt.Circle((x_centre, y_centre), radius, color='red', alpha=0.2)
    ax.add_patch(circle1)
    ax.add_patch(circle2)

    u_vector = mpatches.Patch(color='red', label='uncertainty attack vector')

    ax.scatter([point[0] for point in points['vector'][:1]], [point[1] for point in points['vector'][:1]],
               s=500, c='white', edgecolors='black', marker='s')
    vect = ax.scatter([point[0] for point in points['vector'][1:2]], [point[1] for point in points['vector'][1:2]],
                      s=500, c='white', edgecolors='black', label='vector', marker='s')

    radius, x_centre, y_centre = maximum_x_maximum_y(points_uncertainty[0]['APT'])
    circle1 = plt.Circle((x_centre, y_centre), radius, color='violet')
    radius, x_centre, y_centre = maximum_x_maximum_y(points_uncertainty[1]['APT'])
    circle2 = plt.Circle((x_centre, y_centre), radius, color='violet', alpha=0.7)
    ax.add_patch(circle1)
    ax.add_patch(circle2)

    u_APT = mpatches.Patch(color='violet', label='uncertainty APT')

    ax.scatter([point[0] for point in points['APT'][:1]], [point[1] for point in points['APT'][:1]],
               s=500, c='white', edgecolors='black', marker="p")
    apt = ax.scatter([point[0] for point in points['APT'][1:2]], [point[1] for point in points['APT'][1:2]],
                     s=500, c='white', edgecolors='black', label='APT', marker="p")

    ax.set(xlim=(0, 1), xticks=np.arange(0, 1.01), ylim=(0, 1), yticks=np.arange(0, 1.01))
    ax.legend(loc='upper left', labelspacing=1.5, handleheight=1.7, handlelength=1.5, borderpad=1.0,
              handles=[camp, u_campaign, vuln, u_vuln, vect, u_vector, apt, u_APT])
    xticks = ax.xaxis.get_major_ticks()
    xticks[0].label1.set_visible(False)
    plt.savefig('uncertainty_nodes.png')
    plt.show()

    """Relations"""
    keys_cat = ['attr_to', 'targets', 'employs']
    points = {'attr_to': [], 'targets': [], 'employs': []}

    for key_cat in keys_cat:
        for result in m_l:
            for key in result.keys():
                points[key_cat].append((result[key][key_cat]['rec'], result[key][key_cat]['pr']))

    fig1, ax = plt.subplots()

    ax.set_xlabel('Recall')
    ax.set_ylabel('Precision')

    points['attr_to'] = sorted(points['attr_to'], key=lambda t: t[0] * t[1], reverse=True)
    points['targets'] = sorted(points['targets'], key=lambda t: t[0] * t[1], reverse=True)
    points['employs'] = sorted(points['employs'], key=lambda t: t[0] * t[1], reverse=True)

    plot('attr_to', 'o', points)
    plot('targets', 'h', points)
    plot('employs', 's', points)

    ax.set(xlim=(0, 1), xticks=np.arange(0, 1.01), ylim=(0, 1), yticks=np.arange(0, 1.01))
    ax.legend(loc='upper left', labelspacing=1.5, handleheight=2.5, handlelength=1.5, borderpad=1.0)
    xticks = ax.xaxis.get_major_ticks()
    xticks[0].label1.set_visible(False)
    plt.savefig('validation_relation.png')
    plt.show()

    """Uncertainty points and graphs"""

    points_uncertainty = {0: {'attr_to': [], 'targets': [], 'employs': []},
                          1: {'attr_to': [], 'targets': [], 'employs': []}}
    d_uncertainty = {}
    for i, temperature in enumerate(grid_search['temperature']):
        l_uncertainty = []
        for j in range(10):
            mc.main_metrics(f'../results/campaign_graph/metrics/test/results_{temperature}_3_{j}.xlsx', l_uncertainty,
                            'campaign', 0.80, 0.00)
        d_uncertainty[temperature] = l_uncertainty

    for temperature in [0, 1]:
        print("Temperature: ", temperature)
        for result in d_uncertainty[temperature]:
            print(result)
            for key_cat in keys_cat:
                for key in result.keys():
                    points_uncertainty[temperature][key_cat].append(
                        (result[key][key_cat]['rec'], result[key][key_cat]['pr']))

    print("Hey: ", points_uncertainty)
    fig, ax = plt.subplots()

    ax.set_xlabel('Recall')
    ax.set_ylabel('Precision')

    radius, x_centre, y_centre = maximum_x_maximum_y(points_uncertainty[0]['attr_to'])
    circle1 = plt.Circle((x_centre, y_centre), radius, color='darkmagenta', alpha=0.7)
    radius, x_centre, y_centre = maximum_x_maximum_y(points_uncertainty[1]['attr_to'])
    circle2 = plt.Circle((x_centre, y_centre), radius, color='darkmagenta', alpha=0.2)
    ax.add_patch(circle1)
    ax.add_patch(circle2)

    u_attr_to = mpatches.Patch(color='darkmagenta', label='uncertainty attributed to')

    radius, x_centre, y_centre = maximum_x_maximum_y(points_uncertainty[0]['targets'])
    circle1 = plt.Circle((x_centre, y_centre), radius, color='cyan', alpha=0.7)
    radius, x_centre, y_centre = maximum_x_maximum_y(points_uncertainty[1]['targets'])
    circle2 = plt.Circle((x_centre, y_centre), radius, color='cyan', alpha=0.2)
    ax.add_patch(circle1)
    ax.add_patch(circle2)

    u_targets = mpatches.Patch(color='cyan', label='uncertainty targets')

    ax.scatter([point[0] for point in points['attr_to'][:1]], [point[1] for point in points['attr_to'][:1]],
               s=500, c='white', edgecolors='black', marker="o")
    attr_to = ax.scatter([point[0] for point in points['attr_to'][1:2]], [point[1] for point in points['attr_to'][1:2]],
                         s=500, c='white', edgecolors='black', label='attributed to', marker="o")

    ax.scatter([point[0] for point in points['targets'][:1]], [point[1] for point in points['targets'][:1]],
               s=500, c='white', edgecolors='black', marker="h")
    targets = ax.scatter([point[0] for point in points['targets'][1:2]], [point[1] for point in points['targets'][1:2]],
                         s=500, c='white', edgecolors='black', label='targets', marker="h")

    radius, x_centre, y_centre = maximum_x_maximum_y(points_uncertainty[0]['employs'])
    circle1 = plt.Circle((x_centre, y_centre), radius, color='darkslategray', alpha=0.7)

    radius, x_centre, y_centre = maximum_x_maximum_y(points_uncertainty[1]['employs'])
    circle2 = plt.Circle((x_centre, y_centre), radius, color='darkslategray', alpha=0.2)

    ax.add_patch(circle1)
    ax.add_patch(circle2)

    ax.scatter([point[0] for point in points['employs'][:1]], [point[1] for point in points['employs'][:1]],
               s=500, c='white', edgecolors='black', marker='s')
    employs = ax.scatter([point[0] for point in points['employs'][1:2]], [point[1] for point in points['employs'][1:2]],
                         s=500, c='white', edgecolors='black', label='employs', marker='s')

    u_employs = mpatches.Patch(color='darkslategray', label='uncertainty employs')

    ax.set(xlim=(0, 1), xticks=np.arange(0, 1.01), ylim=(0, 1), yticks=np.arange(0, 1.01))
    ax.legend(loc='upper left', labelspacing=1.5, handleheight=1.5, handlelength=1.5, borderpad=1.0,
              handles=[attr_to, u_attr_to, targets, u_targets, employs, u_employs])
    xticks = ax.xaxis.get_major_ticks()
    xticks[0].label1.set_visible(False)
    plt.savefig('uncertainty_relations.png')
    plt.show()
