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
                with open("nvd_shell.ttl", mode='r', encoding='utf-8') as in_file:
                        shell = in_file.read()
                        out_file.write(shell)
                        
        fn = "cve.ttl"
        with open(fn, mode='w', encoding='utf-8') as out_file:
                
                out_file.write("@prefix cve: <http://www.semanticweb.org/cht_c/cve#> .\n")
                generateShell(out_file)

                for item in root.findall(LS + "Weaknesses/" + LS + "Weakness/" + LS + "Observed_Examples/" + LS + "Observed_Example/" + LS + "Reference"):
                        print(item.text)
                        if item.text.startswith("CVE"): out_file.write("\r:" + item.text + "\r\trdf:type owl:NamedIndividual;\r\trdf:type :CVE .")

def main():
        print("CWE/CVE Ontology Generator, Version 2.0")
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
