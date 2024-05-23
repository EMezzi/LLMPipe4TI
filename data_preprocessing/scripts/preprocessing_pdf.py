from PyPDF2 import PdfReader
import shutil
import json
import os
import re

from miscellaneous.routine_functions import create_json


def replace_ligatures(text: str) -> str:
    ligatures = {
        'Ǻ': 'a', 'ǻ': 'a', 'Č': 'C', 'č': 'c', 'Đ': 'D', 'đ': 'd', 'Ě': 'E', 'ě': 'e', 'Ģ': 'G', 'ģ': 'g',
        'Ħ': 'H', 'ħ': 'h', 'İ': 'I', 'į': 'i', 'Ķ': 'K', 'ķ': 'k', 'Ŀ': 'L', 'ŀ': 'l', 'Ň': 'n', 'ň': 'n',
        'Ǿ': 'O', 'ǿ': 'o', 'Ř': 'R', 'ř': 'r', 'Ș': 'S', 'ș': 's', 'Ț': 'T', 'ț': 't', 'Ų': 'U', 'ų': 'u',
        'Ẅ': 'W', 'ẅ': 'w', 'Ỳ': 'Y', 'ỳ': 'y', 'Ż': 'Z', 'ż': 'z'
    }

    for search, replace in ligatures.items():
        text = text.replace(search, replace)
    return text


def move_broken_pdf(initial_directory, final_directory):
    for report in os.listdir(initial_directory):
        if report[-4:] != '.pdf':
            pass
        else:
            try:
                with open(f'/Users/manu/PycharmProjects/LlmTI/report_sources/pdf_reports/{report}', 'rb') as pdf_report:
                    PdfReader(pdf_report)
            except Exception as e:
                print(f"Exception {e} on report {report}, thus moving it to the other directory broken_pdf")
                shutil.move(initial_directory + report, final_directory + report)


def move_to_json():
    for json_file in os.listdir('../../datasets/campaign_graph'):
        with open('../inferring/dataset_json_graphs/campaign_graph/' + json_file) as f:
            file = json.load(f)
            for title in file['pdf_title']:
                try:
                    with open('discard_pdfs/report_sources_to_be_used/' + title, 'rb') as pdf_report:
                        text_pdf = ""
                        data_pdf = PdfReader(pdf_report)

                        for page in data_pdf.pages:
                            text_pdf += page.extract_text()

                        new_text_pdf = replace_ligatures(text_pdf)

                        print("Title: ", title)
                        create_json('../inferring/pdf_json/' + title[:-4] + '.json', title[:-4], new_text_pdf)
                except Exception as e:
                    print(e, title)


def preprocess_pdf_text():
    for file in os.listdir('../../datasets/pdf_json/'):
        with open(f'../datasets/pdf_json/{file}') as json_file:
            json_object = json.load(json_file)

            print("Title: ", json_object['title'])

            sub_characters = ['\n', '™', '®', '©', '한', '灣', '한', '日', '국', '本', '민', '대', '台', '国', '中',
                              '➎', '➍', '➋', '➌']

            for sub_char in sub_characters:
                json_object['text'] = re.sub(sub_char, ' ', json_object['text'])

            with open(f'../datasets/pdf_json/{file}', 'w', encoding='utf-8') as json_file1:
                json.dump(json_object, json_file1, ensure_ascii=False, indent=4)


if __name__ == '__main__':
    # move_to_json()
    preprocess_pdf_text()
