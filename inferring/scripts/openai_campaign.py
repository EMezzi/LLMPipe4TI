import os
import json
from openai import OpenAI
import shutil

# key = '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'
key = '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'
client = OpenAI(api_key=key)


class GraphExtractor:
    def __init__(self):
        self.key = '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'
        self.client = OpenAI(api_key=self.key)

    @staticmethod
    def save_json(file_path, text):
        json_object = json.loads(text)

        with open(file_path, 'w') as json_file:
            json.dump(json_object, json_file, indent=4)

    @staticmethod
    def query_campaign_graph(temperature, prompt, report):
        """
        :param report: report to be analyzed
        :param temperature: temperature of the model
        :param prompt: prompt for the model
        :return:
        """
        try:
            response = client.chat.completions.create(
                model="gpt-3.5-turbo-1106",
                response_format={"type": "json_object"},
                temperature=temperature,

                messages=[{'role': 'system', 'content': prompt},
                          {'role': 'user', 'content': f"""This is the Cyber Threat report {report}"""}]
            )

            return response.choices[0].message

        except Exception as e:
            print(f"Exception: ", e)

    @staticmethod
    def main_campaign_graph(files_path, path_saving, sampled, temperature, prompt):
        """
        :param files_path: path where there are the dataset files.
        :param saving_path: path where the inferred graphs are saved.
        :param temperature: temperature parameter for the gpt model.
        :param prompt: necessary prompt for the gpt model.
        :return:
        """

        print("Temperature: ", temperature)
        print("Prompt: ", prompt)

        if os.path.exists(path_saving):
            answer = input(f"Sure you want to delete the directory? {path_saving}")
            if answer == 'yes':
                shutil.rmtree(path_saving)
                os.makedirs(path_saving)
        else:
            os.makedirs(path_saving)

        for i, report in enumerate(sampled):
            print("Report: ", i, report)
            with open(f'{files_path}/{report}', 'rb') as file:
                json_file = json.load(file)

                title = json_file['pdf_title']

                print("The title is: ", title)

                if len(title) == 1:
                    with open(f'/Users/manu/PycharmProjects/LlmTI/datasets/pdf_json/{title[0][:-4]}.json',
                              'rb') as file2:
                        json_file2 = json.load(file2)
                        text = json_file2['text']

                        answer = GraphExtractor.query_campaign_graph(temperature, prompt, text)

                        if answer:
                            GraphExtractor.save_json(f'{path_saving}/{report}', answer.content)
