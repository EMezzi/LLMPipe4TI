import os
import json
from openai import OpenAI
import shutil

# key = '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'
key = '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'
client = OpenAI(api_key=key)


def save_json(file_path, object):
    json_object = None
    if isinstance(object, str):
        json_object = json.loads(object)
    elif isinstance(object, dict):
        json_object = object

    if json_object:
        with open(file_path, 'w') as json_file:
            json.dump(json_object, json_file, indent=4)


def query_context_apt(apt_name, temperature):
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo-1106",
            response_format={"type": "json_object"},
            temperature=temperature,
            messages=[{'role': 'system',

                       'content': """You are a Cyber Threat Analyst. I will give you the name of an Advanced Persistent Threat (APT) and I want you to find the following information about it.

                                    Step 1 - Find the country of the APT, all the attack vectors employed by the APT, all the vulnerabilities exploited by the APT. 
                                             
                                             Note: - It is possible to have only one country. 
                                                   - It is possible to have more than one vulnerability. 
                                                   - It is possible to have more than one attack vector.
                                                   - The name of the attack vector can only be one of the following: Credential Dumping, Command-Line Interface, Remote Desktop Protocol, Data from Local System, Data Compressed, Scripting, Process Discovery, Email Collection, Masquerading, System Network Connections Discovery, Account Discovery, Automated Collection, Pass the Hash, Network Share Discovery, System Service Discovery, System Network Configuration Discovery, Unknown, User Execution, Exploitation for Client Execution, Spearphishing Attachment, Web Service, External Remote Services, File and Directory Discovery, Obfuscated Files or Information, Standard Application Layer Protocol, Valid Accounts, Commonly Used Port, Registry Run Keys / Startup Folder, Remote File Copy, Scheduled Task, File Deletion, System Information Discovery, Data Encoding, Regsvr32, Rundll32, System Owner/User Discovery, DLL Side-Loading, Modify Registry, PowerShell, Drive-by Compromise, Modify Existing Service, Deobfuscate/Decode Files or Information, Hidden Window, Data Obfuscation, Replication Through Removable Media, Dynamic Data Exchange, Hidden Files and Directories, Timestomp, Spearphishing Link, Peripheral Device Discovery, Screen Capture, Indicator Removal on Host, Component Object Model Hijacking, Data from Information Repositories, Logon Scripts, Network Sniffing, Bootkit, Exploitation for Privilege Escalation, Exploitation for Defense Evasion, Access Token Manipulation, Data from Removable Media, Data Staged, Trusted Relationship, Communication Through Removable Media, Rootkit, Connection Proxy, Exploitation of Remote Services, Input Capture, Office Application Startup, Template Injection, Custom Cryptographic Protocol, Application Access Token, Steal Application Access Token, Accessibility Features, Bypass User Account Control, Windows Management Instrumentation Event Subscription, Software Packing, Multi-hop Proxy, Windows Management Instrumentation, Pass the Ticket, Domain Fronting, Standard Non-Application Layer Protocol, Shortcut Modification, Redundant Access, Graphical User Interface, Remote System Discovery, Uncommonly Used Port, Permission Groups Discovery, New Service, Multi-Stage Channels, Exfiltration Over Command and Control Channel, Create Account, Indicator Removal from Tools, Account Manipulation, Windows Admin Shares, Brute Force, Credentials in Files, Application Deployment Software, Web Shell, NTFS File Attributes, Binary Padding, Signed Script Proxy Execution, Mshta, Custom Command and Control Protocol, Network Service Scanning, Data Encrypted, Query Registry, Service Execution, File and Directory Permissions Modification, Exfiltration Over Alternative Protocol, Standard Cryptographic Protocol, Execution Guardrails, Audio Capture, Execution through API, Process Injection, Disk Structure Wipe, Code Signing, System Shutdown/Reboot, Clipboard Data, Runtime Data Manipulation, Transmitted Data Manipulation, Stored Data Manipulation, Data Encrypted for Impact, Data Destruction, Remote Services, Domain Generation Algorithms, Supply Chain Compromise, Resource Hijacking, Clear Command History, Fallback Channels, Compiled HTML File, System Time Discovery, Data from Network Shared Drive, Disabling Security Tools, Remote Access Tools, CMSTP, Security Software Discovery, XSL Script Processing, Signed Binary Proxy Execution, Spearphishing via Service, Forced Authentication, Taint Shared Content, Component Firmware, Input Prompt, Video Capture, Application Shimming, Virtualization/Sandbox Evasion, Process Hollowing, AppCert DLLs, Automated Exfiltration, Change Default File Association, Browser Extensions, Application Window Discovery, Multiband Communication, Service Stop, Disk Content Wipe, BITS Jobs, Component Object Model and Distributed COM, Compile After Delivery, Credentials from Web Browsers, Exploit Public-Facing Application, Password Policy Discovery, Hooking, Image File Execution Options Injection, DLL Search Order Hijacking, Windows Remote Management, Data Transfer Size Limits, Network Share Connection Removal, Winlogon Helper DLL, PowerShell Profile.
                                                   - Each node will have an id, compose of the acronym of the node and the number of the entity. 

                                    Step 2 - Return the information filling this json format: 

                                                "nodes": {
                                                    "APT": [
                                                        {
                                                            "name": "", // name of the APT
                                                            "id": "", // id of the APT
                                                        }
                                                    ]
                                                    "country": [
                                                        {
                                                            "name": "", // name of the country the APT is from
                                                            "id": "country1" // id of the country
                                                        }
                                                    ], 
                                                    "attack_vector": [
                                                        {
                                                            "name": "", // name of the attack vector                                       
                                                            "id": "attack_vector1" // id of the attack vector
                                                        }, 
                                                        {
                                                            "name": "", // name of the attack vector
                                                            "id": "attack_vector2" // id of the attack vector
                                                        }
                                                    ]
                                                    "vulnerability": [
                                                        {
                                                            "name": "CVE-yyyy-", // name of the vulnerability                                                  
                                                            "id": "vulnerability1" // id of the vulnerability
                                                        },
                                                        {                                                          
                                                            "name": "CVE-yyyy-", // name of the vulnerability                                                   
                                                            "id": "vulnerability2" // id of the vulnerability
                                                        }
                                                    ]                                      
                                                }
                                  """
                       },

                      {'role': 'user', 'content': f"""This is the name of the APT: {apt_name}"""}]
        )

        return response.choices[0].message

    except Exception as e:
        print(f"Exception: ", e)


def llm_infer_context(path_dataset, path_saving, sampled_context, temperature):
    """
    :return:
    """

    if os.path.exists(path_saving):
        answer = input(f"Sure you want to delete the directory? {path_saving}")
        if answer == 'yes':
            shutil.rmtree(path_saving)
            os.makedirs(path_saving)
    else:
        os.makedirs(path_saving)

    for json_graph in sampled_context:
        print(json_graph)
        with open(f'{path_dataset}/{json_graph}', 'rb') as file:
            json_file = json.load(file)

            # One query version
            actor_name = json_file["nodes"]["APT"][0]["name"]
            answer = query_context_apt(actor_name, temperature)

            if answer:
                save_json(f'{path_saving}/{json_graph}', answer.content)
