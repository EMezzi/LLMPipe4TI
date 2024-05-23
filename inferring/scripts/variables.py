grid_search = {'temperature': [0, 1],
               'prompts': ["""You are a Cyber Threat Analyst. From the Cyber Threat report extract the starting date of 
                              the campaign, Advanced Persistent Threats (APTs), the CVE codes of the vulnerabilities 
                              exploited, and the attack vectors which the APT used.

                              Return the information filling this json format: 

                                      "nodes": {
                                            "campaign": [
                                                {
                                                    "actor": "", // name of the threat actor
                                                    "date_start": ["yyyy-mm", "yyyy-mm"], // list of dates
                                                    "id": "campaign1" // id of the campaign
                                                }
                                            ],
                                            "APT": [
                                                {
                                                    "name": "", // name of the threat actor
                                                    "id": "APT1" // id of the APT
                                                }
                                            ],
                                            "attack_vector": [
                                                {
                                                    "name": "",  // name of the attack vector
                                                    "id": "attack_vector1" // id of the attack vector
                                                },
                                                {
                                                    "name": "", // name of the attack vector
                                                    "id": "attack_vector2" // id of the attack vector
                                                }             
                                            ],
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
                           """,

                           """You are a Cyber Threat Analyst. Use the following step-by-step guide to extract information from cyber threat reports. 

                                   Step 1 - Extract the starting date of the campaign, the Advanced Persistent Threats (APTs), the CVE codes of the vulnerabilities exploited by the APT, and the attack vectors which the APT used.

                                   Note: - The name of the actor in the campaign and the name of the APT must be the same. 
                                         - If there is more than one date available list them all, but always convert them in the indicated format. 
                                         - Only extract the CVE which are directly attributed to the threat actor in the report. 
                                         - Only extract the attack vectors which are directly attributed to the threat actor in the report. 
                                         - It is possible to have more than one vulnerability. 
                                         - It is possible to have more than one attack vector. 
                                         - Each node will have an id, composed by the acronym of the node and the number of the entity.
                                         - If you do not find the name of the attack vector or the vulnerability, do not create the dictionary in the belonging list.
                                         
                                   Step 2 - Extract the relations between the entities gathered. 
                                   Step 3 - Return the information filling in this JSON format:   

                                            "nodes": {
                                                "campaign": [
                                                    {
                                                        "actor": "", // name of the threat actor
                                                        "date_start": ["yyyy-mm", "yyyy-mm"], // list of dates
                                                        "id": "campaign1" // id of the campaign
                                                    }
                                                ],
                                                "APT": [
                                                    {
                                                        "name": "", // name of the threat actor
                                                        "id": "APT1" // id of the APT
                                                    }
                                                ],
                                                "attack_vector": [
                                                    {
                                                        "name": "",  // name of the attack vector
                                                        "id": "attack_vector1" // id of the attack vector
                                                    },
                                                    {
                                                        "name": "", // name of the attack vector
                                                        "id": "attack_vector2" // id of the attack vector
                                                    }             
                                                ],
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
                                            "relations": {
                                                 "attributed_to": [
                                                     [
                                                         "campaign1",
                                                         "APT1"
                                                     ]
                                                 ],
                                                 "targets": [
                                                     [
                                                         "campaign1",
                                                         "vulnerability1"
                                                     ],
                                                     [
                                                         "campaign1",
                                                         "vulnerability2"
                                                     ]
                                                 ],
                                                 "employs": [
                                                     [
                                                         "campaign1",
                                                         "attack_vector1"
                                                     ]
                                                 ]
                                            }
                                   """,

                           """You are a Cyber Threat Analyst. Use the following step-by-step guide to extract information from cyber threat reports. 

                                   Step 1 - Extract the starting date of the campaign, the Advanced Persistent Threats (APTs), the CVE codes of the vulnerabilities exploited by the APT, and the attack vectors which the APT used.

                                   Note: - The name of the actor in the campaign and the name of the APT must be the same. 
                                         - If there is more than one date available list them all, but always convert them in the indicated format. 
                                         - Only extract the CVE which are directly attributed to the threat actor in the report. 
                                         - Only extract the attack vectors which are directly attributed to the threat actor in the report. 
                                         - It is possible to have more than one vulnerability. 
                                         - It is possible to have more than one attack vector. 
                                         - Each node will have an id, composed by the acronym of the node and the number of the entity.
                                         - If you do not find the name of the attack vector or the vulnerability, do not create the dictionary in the belonging list.

                                   Examples for the attack vector: 
                                        "While we cannot be certain how the documents were sent to the targets, phishing emails are highly likely." -> spearphishing attachment
                                        "In the case of Operation Daybreak, the hacked website hosting the exploit kit performs a couple of browser checks before redirecting the visitor to a server controlled by the attackers hosted in Poland." -> drive-by compromise


                                   Step 2 - Extract the relations between the entities gathered. 
                                   
                                   Step 3 - Return the information filling in this JSON format:  

                                            "nodes": {
                                                "campaign": [
                                                    {
                                                        "actor": "", // name of the threat actor
                                                        "date_start": ["yyyy-mm", "yyyy-mm"], // list of dates
                                                        "id": "campaign1" // id of the campaign
                                                    }
                                                ],
                                                "APT": [
                                                    {
                                                        "name": "", // name of the threat actor
                                                        "id": "APT1" // id of the APT
                                                    }
                                                ],
                                                "attack_vector": [
                                                    {
                                                        "name": "",  // name of the attack vector
                                                        "id": "attack_vector1" // id of the attack vector
                                                    },
                                                    {
                                                        "name": "", // name of the attack vector
                                                        "id": "attack_vector2" // id of the attack vector
                                                    }             
                                                ],
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
                                            "relations": {
                                                 "attributed_to": [
                                                     [
                                                         "campaign1",
                                                         "APT1"
                                                     ]
                                                 ],
                                                 "targets": [
                                                     [
                                                         "campaign1",
                                                         "vulnerability1"
                                                     ],
                                                     [
                                                         "campaign1",
                                                         "vulnerability2"
                                                     ]
                                                 ],
                                                 "employs": [
                                                     [
                                                         "campaign1",
                                                         "attack_vector1"
                                                     ]
                                                 ]
                                            }
                           """,
                           """You are a Cyber Threat Analyst. Use the following step-by-step guide to extract information from cyber threat reports. 

                                   Step 1 - Extract the starting date of the campaign, the Advanced Persistent Threats (APTs), the CVE codes of the vulnerabilities exploited by the APT, and the attack vectors which the APT used.

                                            Note: - The name of the actor in the campaign and the name of the APT must be the same. 
                                                  - If there is more than one date available list them all, but always convert them in the indicated format. 
                                                  - Only extract the CVE which are directly attributed to the threat actor in the report. 
                                                  - Only extract the attack vectors which are directly attributed to the threat actor in the report. 
                                                  - It is possible to have more than one vulnerability. 
                                                  - It is possible to have more than one attack vector. 
                                                  - The name of the attack vector can only be one of the following: drive-by compromise, supply chain compromise, exploit public-facing application, spearphishing via service, spearphishing attachment, valid accounts, external remote services, spearphishing link.
                                                  - In case the attack vector is unknown assign to it 'unknown'. 
                                                  - Each node will have an id, composed of the acronym of the node and the number of the entity.
                                                  - If you do not find the name of the attack vector or the vulnerability, do not create the dictionary in the belonging list.

                                            Here are some examples to help understand which was the attack vector used by the APT: 
                                                "to configure a client-side mail rule crafted to download and execute a malicious payload from an adversary-controlled WebDAV server" -> spearphishing attachment. 
                                                "We also confirmed that the user installed this program via a download link delivered over email." -> spearphishing link. 
                                                "the sites, which appear to be Outlook Web Access, Yahoo, and Google login pages, have been leveraged in spear-phishing messages." -> spearphishing via service.
                                                "has been linked to a watering hole attack" -> drive-by compromise.
                                                "Initial Access External Remote Services" -> external remote services.
                                                "employed legitimate user credentials to access its targets' networks." -> valid accounts. 
                                                
                                   Step 2 - Extract the relations between the entities gathered. 
                                   
                                   Step 3 - Return the information filling in this JSON format: 

                                            "nodes": {
                                                "campaign": [
                                                   {
                                                       "actor": "", // name of the threat actor
                                                       "date_start": ["yyyy-mm", "yyyy-mm"], // list of dates
                                                       "id": "campaign1" // id of the campaign
                                                   }
                                                ],
                                                "APT": [
                                                   {
                                                       "name": "", // name of the threat actor
                                                       "id": "APT1" // id of the APT
                                                   }
                                               ],
                                               "attack_vector": [
                                                   {
                                                       "name": "",  // name of the attack vector
                                                       "id": "attack_vector1" // id of the attack vector
                                                   },
                                                   {
                                                       "name": "", // name of the attack vector
                                                       "id": "attack_vector2" // id of the attack vector
                                                   }             
                                               ],
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
                                            "relations": {
                                                 "attributed_to": [
                                                     [
                                                         "campaign1",
                                                         "APT1"
                                                     ]
                                                 ],
                                                 "targets": [
                                                     [
                                                         "campaign1",
                                                         "vulnerability1"
                                                     ],
                                                     [
                                                         "campaign1",
                                                         "vulnerability2"
                                                     ]
                                                 ],
                                                 "employs": [
                                                     [
                                                         "campaign1",
                                                         "attack_vector1"
                                                     ]
                                                 ]
                                            }
                           """
                           ]}

json_validation_campaign = ['259.json', '253.json', '305.json', '88.json', '233.json', '173.json', '311.json',
                            '99.json', '35.json', '190.json', '15.json', '218.json', '14.json', '59.json', '45.json',
                            '111.json', '103.json', '206.json', '2.json', '203.json', '294.json', '130.json',
                            '325.json', '289.json', '213.json', '296.json', '3.json', '333.json', '193.json',
                            '247.json', '196.json', '270.json', '209.json', '77.json', '200.json', '10.json',
                            '1.json', '139.json', '107.json', '131.json', '91.json', '49.json', '17.json', '228.json',
                            '65.json', '89.json', '312.json', '249.json', '210.json', '69.json', '227.json', '264.json',
                            '157.json', '75.json', '290.json', '147.json', '6.json', '121.json', '188.json', '141.json',
                            '266.json', '56.json', '60.json', '256.json', '216.json', '25.json', '109.json', '208.json',
                            '76.json', '0.json', '235.json', '163.json', '197.json', '164.json', '328.json', '207.json',
                            '338.json', '162.json', '28.json', '105.json', '38.json', '136.json', '64.json', '242.json',
                            '53.json', '192.json', '263.json', '71.json', '229.json', '255.json', '117.json', '297.json',
                            '132.json', '172.json', '29.json', '20.json', '217.json', '144.json', '100.json', '237.json',
                            '243.json', '135.json', '223.json', '12.json', '267.json', '323.json', '212.json',
                            '257.json', '286.json', '248.json', '134.json', '187.json', '33.json', '310.json', '148.json',
                            '198.json', '4.json', '72.json', '246.json', '302.json', '161.json', '191.json', '321.json',
                            '251.json', '145.json', '204.json', '271.json', '234.json', '219.json', '180.json',
                            '159.json', '87.json', '66.json', '244.json', '230.json', '140.json', '138.json',
                            '106.json', '260.json', '62.json', '26.json', '326.json', '52.json', '285.json', '258.json',
                            '252.json', '167.json', '238.json', '335.json', '336.json', '300.json', '332.json',
                            '74.json', '272.json', '250.json', '92.json', '224.json', '189.json', '160.json', '166.json',
                            '182.json', '334.json', '50.json', '327.json', '73.json', '47.json', '21.json', '101.json',
                            '225.json', '301.json', '194.json', '110.json', '299.json', '24.json']

json_test_campaign = ['104.json', '108.json', '112.json', '119.json', '128.json', '129.json', '133.json', '142.json',
                      '143.json', '146.json', '155.json', '156.json', '168.json', '169.json', '170.json', '171.json',
                      '174.json', '18.json', '181.json', '183.json', '184.json', '185.json', '186.json', '19.json',
                      '195.json', '201.json', '214.json', '215.json', '220.json', '221.json', '222.json', '232.json',
                      '236.json', '239.json', '240.json', '241.json', '245.json', '265.json', '269.json', '287.json',
                      '291.json', '292.json', '295.json', '30.json', '306.json', '31.json', '313.json', '315.json',
                      '320.json', '324.json', '330.json', '337.json', '339.json', '340.json', '37.json', '40.json',
                      '43.json', '46.json', '48.json', '51.json', '54.json', '55.json', '61.json', '63.json', '67.json',
                      '68.json', '7.json', '70.json', '86.json', '9.json', '90.json', '93.json', '97.json', '98.json']

sampled_context = ['76.json', '57.json', '28.json', '29.json', '38.json', '63.json', '77.json', '37.json', '44.json',
                   '50.json', '7.json', '81.json', '1.json', '54.json', '65.json', '47.json', '27.json', '25.json',
                   '84.json', '35.json', '46.json', '75.json', '48.json', '32.json', '5.json', '15.json', '67.json',
                   '64.json', '6.json', '72.json', '20.json', '42.json', '36.json', '43.json', '30.json', '22.json',
                   '24.json', '26.json', '49.json', '45.json', '31.json', '18.json', '14.json', '56.json', '16.json',
                   '68.json', '13.json', '23.json', '4.json', '2.json', '71.json', '58.json', '82.json', '51.json',
                   '21.json', '70.json', '12.json', '11.json', '10.json', '74.json']
