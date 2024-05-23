import numpy as np
import pandas as pd
import re

if __name__ == '__main__':
    threat_vuln = pd.read_excel('./rel_threatactor_vulnerabilities.xlsx')

    print(threat_vuln)
    if "primary source pdf" not in threat_vuln:
        threat_vuln['primary source pdf'] = ""

    empty = [col for col in threat_vuln.columns if threat_vuln[col].isna().all()]
    threat_vuln.drop(columns=empty, inplace=True)

    threat_vuln.set_index('primary source', inplace=True)

    reports = list(set(list(threat_vuln.index)))
    reports = [report for report in reports if isinstance(report, str)]

    dict_names = {}
    for report in reports:
        report1 = re.sub(r'//', '/', report.strip())
        components = [x for x in report1.split('/') if x != '']
        dict_names[report] = components[-1]

    dict_names = {key: re.sub(r'\.html', '.pdf', dict_names[key])
                  for key in dict_names.keys()}

    dict_names = {key: dict_names[key] + '.pdf' if dict_names[key][-4:] != '.pdf' else dict_names[key]
                  for key in dict_names.keys()}

    threat_vuln = threat_vuln.reset_index()

    print("Let's count the ones that are directly openable")
    s = 0
    for key in dict_names.keys():
        try:
            with open(f'../../report_sources/pdf_reports/{dict_names[key]}', 'rb'):
                threat_vuln.loc[threat_vuln['primary source'] == key, 'primary source pdf'] = dict_names[key]
                s += 1
        except Exception as e:
            print(f"Exception {e}")

    threat_vuln.to_excel('rel_threatactor_vulnerabilities.xlsx', index=False)
    print(s)
