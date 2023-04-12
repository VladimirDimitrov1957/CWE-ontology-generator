import urllib.request, zipfile
import xml.etree.ElementTree as etree
from datetime import datetime

LS = "{http://cwe.mitre.org/cwe-6}"

def parseXML():
        xml_fn = "data/cwec.xml"
        tree = etree.parse(xml_fn)
        return tree.getroot()

def generateIndividuals(root):
        
        def generateShell(out_file):
                with open("capec_shell.ttl", mode='r', encoding='utf-8') as in_file:
                        shell = in_file.read()
                        out_file.write(shell)
                        
        fn = "capec.ttl"
        with open(fn, mode='w', encoding='utf-8') as out_file:

                generateShell(out_file)

                for item in root.findall(LS + "Weaknesses/" + LS + "Weakness/" + LS + "Related_Attack_Patterns/" + LS + "Related_Attack_Pattern"):
                        print("CAPEC-" + item.attrib["CAPEC_ID"])
                        out_file.write("\r:CAPEC-" + item.attrib["CAPEC_ID"] + "\r\trdf:type owl:NamedIndividual;\r\trdf:type :CAPEC .")

def main():
        print("CWE/CAPEC Ontology Generator, Version 2.0")
        start = datetime.now()
        print(start)
        root = parseXML()
        generateIndividuals(root)
        print("Generation end")
        end = datetime.now()
        print(end)
        print(f"Elapsed: {end - start}")

if __name__ == "__main__":
        main()
