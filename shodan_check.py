from shodan import Shodan
import csv
import json
from googletrans import Translator #pip3 install googletrans==3.1.0a0
import sys

translator = Translator()
api = Shodan("YOUR_API_KEY_HERE")

userInput = input('Enter IP: ')

try:
    results = api.host(f'{userInput}')
except:
    print("Unexpected error:", sys.exc_info()[0])
    sys.exit()

with open(userInput+'.csv', 'w', newline='', encoding='utf-8') as csv_file:  
    writer = csv.writer(csv_file)
    writer.writerow(["CVE", "CVSS", "Resume", "References"])
    results=json.dumps(results)
    results=json.loads(results)

    contador=0

    while (True):
        try:
            #Intento encontrar la raiz de vulns, recojo los datos y rompo cuando los encuentre
            for item in results['data'][contador]['vulns']:
                cve = item
                print("Adding "+cve)
                cvss = results['data'][contador]['vulns'][item]['cvss']
                summary = results['data'][contador]['vulns'][item]['summary']
                summary = translator.translate(summary, dest='es').text #Change this to your language if you want, by default is Spanish
                references = results['data'][contador]['vulns'][item]['references']
                writer.writerow([cve, cvss, summary,references])
            break
        except:
            contador=contador+1
            if(contador==10):
                print("No vulnerabilities found")
                break
            else:
                continue
            
csv_file.close()
