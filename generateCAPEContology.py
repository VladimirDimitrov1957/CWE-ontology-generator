import urllib.request, re, sys, zipfile, argparse, cpe
import xml.etree.ElementTree as etree
from datetime import datetime

LS = "{http://cwe.mitre.org/cwe-6}"

def parseXML():
        xml_fn = "data/cwec.xml"
        tree = etree.parse(xml_fn)
        return tree.getroot()

def generateIndividuals(root):
        
        def generateShell(out_file):
                with open("capec_shell.owl", mode='r', encoding='utf-8') as in_file:
                        shell = in_file.read()
                        out_file.write(shell)
                        
        fn = "capec.owl"
        out_file = open(fn, mode='w', encoding='utf-8')
        out_file.write("Prefix: capec: <http://www.semanticweb.org/cht_c/capec#>\n")
        generateShell(out_file)

        for item in root.findall(LS + "Weaknesses/" + LS + "Weakness/" + LS + "Related_Attack_Patterns/" + LS + "Related_Attack_Pattern"):
                print("CAPEC-" + item.attrib["CAPEC_ID"])
                out_file.write("\nIndividual: capec:CAPEC-" + item.attrib["CAPEC_ID"] + "\n\tTypes:\n\t\tCAPEC")

def main(download):
        print("CVE Ontology Generator, Version 1.0")
        start = datetime.now()
        print(start)
        if download:
                print("Download CWE List")
                downloadCWE()
        root = parseXML()
        generateIndividuals(root)
        print("Generation end")
        end = datetime.now()
        print(end)
        print(f"Elapsed: {end - start}")

if __name__ == "__main__":
        parser = argparse.ArgumentParser()
        parser.add_argument('-d', '--download', action="store_true", help='download input from the Web')
        args = parser.parse_args()
        main(args.download)
