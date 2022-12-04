"""CWE ontology generator.

The generator downloads the current version of CWE List from MITRE site and then generates OWL Manchester syntax ontology.
The dictionary is downloaded as .zip file and then it is unzipped.
The ontology is generated with the file name "cwe.owl".
"""

import urllib.request, re, sys, zipfile, argparse, cpe
import re, os
import xml.etree.ElementTree as etree
import lxml.etree
from datetime import datetime

LS = "{http://cwe.mitre.org/cwe-6}"
xml_fn = "data/cwec.xml"

def code(s):
        return s.replace("\\", "\\\\").replace("\"", "\\\"")

def flat(s):
        return " ".join([e.strip() for e in s.strip().splitlines()])
               
def stext(s, tag):
        r = re.sub("<ns0:" + tag + " xmlns:html=\"http://www.w3.org/1999/xhtml\" xmlns:ns0=\"http://cwe.mitre.org/cwe-6\".*?>", "", s)
        r = re.sub("<ns0:" + tag + " xmlns:ns0=\"http://cwe.mitre.org/cwe-6\".*?>", "", r)
        return flat(r.replace("</ns0:" + tag + ">", ""))

class Weakness:
        def __init__(self, element):
                assert isinstance(element, etree.Element)
                self.element = element
                self.IRI = "CWE-" + element.attrib["ID"] 
                self.annotations = dict()
                self.data_facts = dict()
                self.object_facts = dict()
                self.types = set()
                
        def addType(self, aName):
                if aName == "Category":
                        self.types.add("Category")
                else:
                        self.types.add(self.element.attrib[aName])
                
        def addDataFact(self, tag, path = "", structured = False):
                for e in self.element.findall(path + LS + tag):
                        if structured:
                                value = stext(etree.tostring(e).decode('UTF-8'), tag)
                        else:
                                value = flat(e.text)
                        value = code(value)
                        if tag not in self.data_facts: self.data_facts[tag] = dict()
                        vd = self.data_facts[tag]
                        ad = dict()
                        vd[value] = ad
                        self.data_facts[tag] = vd
                        
        def addDataFactFromAttribute(self, att):
                if att in self.element.attrib:
                        value = flat(self.element.attrib[att])
                        value = code(value)
                        if att not in self.data_facts: self.data_facts[att] = dict()
                        vd = self.data_facts[att]
                        ad = dict()
                        vd[value] = ad
                        self.data_facts[att] = vd
                        
        def addDataFactWithAnnotation(self, tag, aTag, path = "", name = None, aName = None, structured = False):
                if name is None:
                        n = tag
                else:
                        n = name
                if aName is None:
                        an = aTag
                else:
                        an = aName
                for e in self.element.findall(path + LS + tag):
                        value = code(flat(e.text))
                        if n not in self.data_facts: self.data_facts[n] = dict()
                        fd = self.data_facts[n]
                        if value not in fd: fd[value] = dict()
                        vd = fd[value]
                        if an not in vd: vd[an] = list()
                        al = vd[an]
                        for ae in self.element.findall(path + LS + aTag):
                                if structured:
                                        aValue = stext(etree.tostring(ae).decode('UTF-8'), aTag)
                                else:
                                        aValue = flat(ae.text)
                                al.append(code(aValue),)
                        vd[an] = al
                        fd[value] = vd
                        self.data_facts[n] = fd
        
        def addAnnotation(self, tag, name = None, path = "", structured = False):
                if name is None:
                        n = tag
                else:
                        n = name
                for e in self.element.findall(path + LS + tag):
                        if structured:
                                value = stext(etree.tostring(e).decode('UTF-8'), tag)
                        else:
                                value = flat(e.text)
                        if name not in self.annotations: self.annotations[n] = list()
                        l = self.annotations[n]
                        l.append(code(value))
                        self.annotations[n] = l
        
        def addReferences(self):
                path = LS + "References/" + LS + "Reference"
                name = "Reference"
                for e in self.element.findall(path):
                        if name not in self.annotations: self.annotations[name] = list()
                        l = self.annotations[name]
                        value = "External reference ID: " + e.attrib["External_Reference_ID"]
                        if "Section" in e.attrib: value += "\nSection: " + e.attrib["Section"]
                        l.append(code(value))
                        self.annotations[name] = l

        def addContentHystory(self):
                path = LS + "Content_History"
                e = self.element.find(path)
                el = e.find(LS + "Submission")
                if el is not None:
                        r = "Submission:"
                        for s in el.findall(LS + "Submission_Name"):
                                r += "\n\tSubmission Name: " + code(s.text)
                        for s in el.findall("Submission_Organization"):
                                r += "\n\tSubmission Organization: " + code(s.text)
                        s = el.find(LS + "Submission_Date")
                        if s is not None: r += "\n\tSubmission Date: " + code(s.text)
                        s = el.find(LS + "Submission_Comment")
                        if s is not None: r += "\n\tSubmission Comment: " + code(s.text)
                for el in e.findall(LS + "Modification"):
                        r += "\nModification:"
                        s = el.find("Modification_Name")
                        if s is not None: r += "\n\tModification Name: " + code(s.text)
                        s = el.find(LS + "Modification_Organization")
                        if s is not None: r += "\n\tModification Organization: " + code(s.text)
                        s = el.find(LS + "Modification_Date")
                        if s is not None: r += "\n\tModification Date: " + code(s.text)
                        s = el.find(LS + "Modification_Importance")
                        if s is not None: r += "\n\tModification Importance: " + code(s.text)
                        s = el.find(LS + "Modification_Comment")
                        if s is not None: r += "\n\tModification Comment: " + code(s.text)
                for el in e.findall(LS + "Contribution"):
                        r += "\nContribution:"
                        s = el.find("Contribution_Name")
                        if s is not None: r += "\n\tContribution Name: " + code(s.text)
                        s = el.find(LS + "Contribution_Organization")
                        if s is not None: r += "\n\tContribution Organization: " + code(s.text)
                        s = el.find(LS + "Contribution_Date")
                        if s is not None: r += "\n\tContribution Date: " + code(s.text)
                        s = el.find(LS + "Contribution_Comment")
                        if s is not None: r += "\n\tContribution Comment: " + code(s.text)
                        r += "\n\tType: " + code(el.attrib["Type"])
                for el in e.findall(LS + "Previous_Entry_Name"):
                        r += "\nPrevious Entry Name: " + code(el.text)
                        r += "\n\tDate: " + el.attrib["Date"]
                self.annotations["Content_History"] = (r,)

        def addObjectFact(self, path, oName, cName, cADict):
                count = 0
                for e in self.element.findall(path + LS + cName):
                        if oName not in self.object_facts: self.object_facts[oName] = list()
                        ol= self.object_facts[oName]
                        name = self.IRI + "_" + cName + str(count)
                        ind = Individual(name)
                        ind.addType(cName)
                        for k, v in cADict.items():
                                if k in e.attrib: ind.addDataFact(v, code(e.attrib[k]))
                        ol.append(name,)
                        self.object_facts[oName] = ol
                        count += 1

        def addObjectFactWithAnnotation(self, path, oName, cName, cADict = {}, cSDict = {}, cANDict = {}, references = False, note = False):
                count = 0
                for e in self.element.findall(path):
                        if oName not in self.object_facts: self.object_facts[oName] = list()
                        ol = self.object_facts[oName]
                        name = self.IRI + "_" + cName + str(count)
                        ind = Individual(name)
                        ind.addType(cName)
                        for k, v in cADict.items():
                                if k in e.attrib: ind.addDataFact(v, code(e.attrib[k]))
                        for k, v in cSDict.items():
                                for el in e.findall(LS + k):
                                        if v == "Observed_Example_Reference":
                                                if el.text.startswith("CVE"):
                                                        ind.addObjectFact(v, "cve:" + el.text)
                                                else:
                                                        ind.addAnnotation("Reference", el.text)
                                        else:
                                                ind.addDataFact(v, code(el.text))
                        for k, v in cANDict.items():
                                for el in e.findall(LS + k):
                                        if v[1]:
                                                ind.addAnnotation(v[0], code(stext(etree.tostring(el).decode('UTF-8'), k)))
                                        else:
                                                ind.addAnnotation(v[0], code(el.text))
                        if note: ind.addAnnotation("Note_Description", code(stext(etree.tostring(e).decode('UTF-8'), "Note")))
                        ol.append(name,)
                        self.object_facts[oName] = ol
                        if references:
                                for ref in e.findall(LS + "References/" + LS + "Reference"):
                                        an = "External reference ID: " + ref.attrib["External_Reference_ID"]
                                        if "Section" in ref.attrib: an += "\nSection: " + ref.attrib["Section"]
                                        ind.addAnnotation("Reference", code(an))
                        count += 1
                        
        def addCAPEC(self):
                els = self.element.findall(LS + "Related_Attack_Patterns/" + LS + "Related_Attack_Pattern")
                if not els: return 
                oName = "Related_Attack_Pattern"
                if oName not in self.object_facts: self.object_facts[oName] = list()
                ol = self.object_facts[oName]
                for e in  els:
                        ol.append("capec:CAPEC-" + e.attrib["CAPEC_ID"],)
                self.object_facts[oName] = ol
     
        def tostring(self):
                r = "\nIndividual: " + self.IRI + "\n\tTypes:"
                first = True
                for t in self.types:
                        if first:
                                first = False
                        else:
                                r += ","
                        r += "\n\t\t" + t
                if self.annotations:
                        r += "\n\tAnnotations:"
                        first = True
                        for a, l in self.annotations.items():
                                for v in l:
                                        if first:
                                                first = False
                                        else:
                                                r += ","
                                        r += "\n\t\t" + a + " \"" + v + "\""
                first = True
                if self.data_facts:
                        r += "\n\tFacts:"
                        for f, fd in self.data_facts.items():
                                for fv, ad in fd.items():
                                        if first:
                                                first = False
                                        else:
                                                r += ","
                                        firstAnnot = True
                                        for a, avl in ad.items():
                                                for av in avl:
                                                        if firstAnnot:
                                                                r += "\n\t\tAnnotations:"
                                                                firstAnnot = False
                                                        else:
                                                                r += ","
                                                        r += "\n\t\t\t" + a + " \"" + av + "\""
                                        r += "\n\t\t\t" + f + " \"" + fv + "\""
                if self.object_facts:
                        if first: r += "\n\tFacts:"
                        for f, fl in self.object_facts.items():
                                for ind in fl:
                                        if first:
                                                first = False
                                        else:
                                                r += ","
                                        r += "\n\t\t\t" + f + " " + ind
                return r
        
        def addMembers(self, relationships = False):
                if relationships:
                        path = LS + "Relationships"
                else:
                        path = LS + "Members"
                e = self.element.find(path)
                if e is not None:
                        for el in e.findall(LS + "Member_Of"):
                                oName = "cwe-" + str(el.attrib["View_ID"]) + ":Member_Of"
                                if oName not in self.object_facts: self.object_facts[oName] = list()
                                ol = self.object_facts[oName]
                                ol.append("cwe-" + str(el.attrib["CWE_ID"]),)
                                self.object_facts[oName] = ol
                        for el in e.findall(LS + "Has_Member"):
                                oName = "cwe-" + str(el.attrib["View_ID"]) + ":Has_Member"
                                if oName not in self.object_facts: self.object_facts[oName] = list()
                                ol = self.object_facts[oName]
                                ol.append("CWE-" + str(el.attrib["CWE_ID"]),)
                                self.object_facts[oName] = ol
                                
        def addRelatedWeaknesses(self):
                path = LS + "Related_Weaknesses"
                e = self.element.find(path)
                if e is not None:
                        for el in e.findall(LS + "Related_Weakness"):
                                vs = el.attrib["View_ID"]
                                nat = el.attrib["Nature"]
                                if vs == 709 and nat in {"StartsWith", "CanPrecede", "CanFollow"} and el.attib["Chain_ID"] is not None:
                                        oName = "cwe-709:" + nat
                                else:
                                        oName = "cwe-" + str(vs) + ":" + nat
                                if "Ordinal" in el.attrib: oName += "-Primary"
                                if oName not in self.object_facts: self.object_facts[oName] = list()
                                ol = self.object_facts[oName]
                                ol.append("CWE-" + str(el.attrib["CWE_ID"]),)
                                self.object_facts[oName] = ol
                                
        def addContent(self, viewID, cweID):
                oName = "cwe-" + str(viewID) + ":Has_Member"
                if oName not in self.object_facts: self.object_facts[oName] = list()
                ol = self.object_facts[oName]
                ol.append("CWE-" + cweID,)
                self.object_facts[oName] = ol
                
        def addDemonstrativeExamples(self):
                path = LS + "Demonstrative_Examples/" + LS + "Demonstrative_Example"
                oName = "Demonstrative_Example"
                aName = "Demonstrative_Example_ID"
                count = 0
                for e in self.element.findall(path):
                        if oName not in self.object_facts: self.object_facts[oName] = list()
                        ol = self.object_facts[oName]
                        name = self.IRI + "_" + oName + str(count)
                        ind = Individual(name)
                        ind.addType(oName)
                        if aName in e.attrib: ind.addDataFact(aName, code(e.attrib[aName]))
                        tt = "Title_Text"
                        se = e.find(LS + tt)
                        if se is not None: ind.addAnnotation(tt, code(se.text))
                        it = "Intro_Text"
                        se = e.find(LS + it)
                        if se is not None: ind.addAnnotation(it, code(stext(etree.tostring(se).decode('UTF-8'), it)))
                        bt = "Body_Text"
                        for b in e.findall(LS + bt):
                                ind.addAnnotation(bt, code(stext(etree.tostring(b).decode('UTF-8'), bt)))
                        ec = "Example_Code"
                        count2 = 0
                        for sc in e.findall(LS + ec):
                                name2 = name + "_EC" + str(count2)
                                ind.addObjectFact(ec, name2)
                                ind2 = Individual(name2)
                                ind2.addType(ec)
                                ind2.addDataFact("Nature", sc.attrib["Nature"])
                                if "Language" in sc.attrib: ind2.addDataFact("Language", sc.attrib["Language"])
                                ind2.addAnnotation("Structured_Code", code(stext(etree.tostring(sc).decode('UTF-8'), "Example_Code")))
                                count2 += 1
                        ol.append(name,)
                        self.object_facts[oName] = ol
                        for ref in e.findall(LS + "References/" + LS + "Reference"):
                                an = "External reference ID: " + ref.attrib["External_Reference_ID"]
                                if "Section" in ref.attrib: an += "\nSection: " + ref.attrib["Section"]
                                ind.addAnnotation("Reference", code(an))
                        count += 1
                
class Individual:
        extend = set()
        def __init__(self, name):
                self.name = name
                self.types = set()
                self.annotations = dict()
                self.data_facts = dict()
                self.object_facts = dict()
                Individual.extend.add(self)
        def addType(self, t):
                self.types.add(t,)
        def addDataFact(self, d, v):
                if d not in self.data_facts: self.data_facts[d] = set()
                ds = self.data_facts[d]
                ds.add(v,)
                self.data_facts[d] = ds
        def addObjectFact(self, d, v):
                if d not in self.object_facts: self.object_facts[d] = set()
                ds = self.object_facts[d]
                ds.add(v,)
                self.object_facts[d] = ds
        def addAnnotation(self, a, v):
                if a not in self.annotations: self.annotations[a] = set()
                s = self.annotations[a]
                s.add(v,)
                self.annotations[a] = s
        def tostring(self):
                r = "\nIndividual: " + self.name
                if self.types:
                        r += "\n\tTypes:"
                        first = True
                        for t in self.types:
                                if first:
                                        first = False
                                else:
                                        r += ","
                                r += "\n\t\t" + t
                if self.annotations:
                        r += "\n\tAnnotations:"
                        first = True
                        for a, av in self.annotations.items():
                                for l in av:
                                        if first:
                                                first = False
                                        else:
                                                r += ","
                                        r += "\n\t\t\t" + a + " \"" + l + "\""
                first = True
                if self.data_facts:
                        r += "\n\tFacts:"
                        for f, fv in self.data_facts.items():
                                for v in fv:
                                        if first:
                                                first = False
                                        else:
                                                r += ","
                                        if f == "Link":
                                                 r += "\n\t\t\t" + f + " \"" + v + "\"^^xsd:anyURI"
                                        else:
                                                r += "\n\t\t\t" + f + " \"" + v + "\""
                if self.object_facts:
                        if first: r += "\n\tFacts:"
                        for f, fv in self.object_facts.items():
                                for v in fv:
                                        if first:
                                                first = False
                                        else:
                                                r += ","
                                        if f == "CPE_ID":
                                                r += "\n\t\t\tCPE_ID " + convert_fs_to_compressed_uri(v)
                                        else:
                                                r += "\n\t\t\t" + f + " " + v
                return r
                                

def downloadCWE():
        url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
        fileName = "data/cwec_latest.xml.zip"
        with urllib.request.urlopen(url) as response:
                contents = response.read()
                with open(fileName, mode='wb') as out_file:
                        out_file.write(contents)
        with zipfile.ZipFile(fileName, 'r') as zip_ref:
            zip_ref.extractall(path="data")
            xml = os.replace("data/" + zip_ref.namelist()[0], "data/cwec.xml")

def parseXML():
        tree = etree.parse(xml_fn)
        return tree.getroot()

def generateWeaknessIndividual(item, out_file):
        weakness = Weakness(item)
        weakness.addAnnotation("Description", name = "Weakness_Description")
        weakness.addAnnotation("Extended_Description", structured = True)
        weakness.addRelatedWeaknesses()
        weakness.addAnnotation("Background_Detail", path = LS + "Background_Details/", structured = True)
        weakness.addAnnotation("Exploitation_Factor", path = LS + "Exploitation_Factors/", structured = True)
        weakness.addType("Abstraction")
        weakness.addType("Structure")
        weakness.addType("Status")
        weakness.addDataFactFromAttribute("Name")
        weakness.addDataFactWithAnnotation("Ordinality", "Description", path = LS + "Weakness_Ordinalities/" + LS + "Weakness_Ordinality/", name = "Weakness_Ordinality", aName = "Weakness_Ordinality_Description")
        weakness.addDataFactWithAnnotation("Term", "Description", path = LS + "Alternate_Terms/" + LS + "Alternate_Term/", name = "Alternate_Term", aName = "Alternate_Term_Description", structured = True)
        weakness.addDataFact("Likelihood_Of_Exploit")
        weakness.addDataFact("Functional_Area", path = LS + "Functional_Areas/")
        lang = {"Name":"LanguageName", "Class":"LanguageClass", "Prevalence":"Prevalence"}
        weakness.addObjectFact(LS + "Applicable_Platforms/", "Applicable_Platform", "Language", lang)
        os = {"Name":"OperatingSystemName", "Class":"OperatingSystemClass", "Prevalence":"Prevalence", "Version":"Version", "CPE_ID":"CPE_ID"}
        weakness.addObjectFact(LS + "Applicable_Platforms/", "Applicable_Platform", "Operating_System", os)
        arch = {"Name":"ArchitectureName", "Class":"ArchitectureClass", "Prevalence":"Prevalence"}
        weakness.addObjectFact(LS + "Applicable_Platforms/", "Applicable_Platform", "Architecture", arch)
        tech = {"Name":"TechnologyName", "Class":"TechnologyClass", "Prevalence":"Prevalence"}
        weakness.addObjectFact(LS + "Applicable_Platforms/", "Applicable_Platform", "Technology", tech)
        ca = {"Consequence_ID":"Consequence_ID"}
        ce = {"Scope":"Scope", "Impact":"Impact", "Likelihood":"Likelihood"}
        can = {"Note":("Consequence_Note", True)}
        weakness.addObjectFactWithAnnotation(LS + "Common_Consequences/" + LS + "Consequence", "Common_Consequence", "Consequence", cADict = ca, cSDict = ce, cANDict = can)
        ca = {"Detection_Method_ID":"Detection_Method_ID"}
        ce = {"Method":"Method", "Effectiveness":"Detection_Effectiveness"}
        can = {"Description":("Detection_Method_Description", True), "Effectiveness_Notes":("Effectiveness_Note", True)}
        weakness.addObjectFactWithAnnotation(LS + "Detection_Methods/" + LS + "Detection_Method", "Detection_Method", "Detection_Method", cADict = ca, cSDict = ce, cANDict = can)
        ca = {"Mitigation_ID":"Mitigation_ID"}
        ce = {"Phase":"Phase", "Strategy":"Strategy", "Effectiveness":"Effectiveness"}
        can = {"Description":("Potential_Mitigation_Description", True), "Effectiveness_Notes":("Effectiveness_Note", True)}
        weakness.addObjectFactWithAnnotation(LS + "Potential_Mitigations/" + LS + "Mitigation", "Potential_Mitigation", "Potential_Mitigation", cADict = ca, cSDict = ce, cANDict = can)
        weakness.addDemonstrativeExamples()
        ce = {"Link":"Link", "Reference":"Observed_Example_Reference"}
        can = {"Description":("Observed_Example_Description", True)}
        weakness.addObjectFactWithAnnotation(LS + "Observed_Examples/" + LS + "Observed_Example", "Observed_Example", "Observed_Example", cSDict = ce, cANDict = can)
        weakness.addDataFact("Affected_Resource", path = LS + "Affected_Resources/")
        ca = {"Taxonomy_Name":"Taxonomy_Name"}
        ce = {"Entry_ID":"Entry_ID", "Entry_Name":"Entry_Name", "Mapping_Fit":"Mapping_Fit"}
        weakness.addObjectFactWithAnnotation(LS + "Taxonomy_Mappings/" + LS + "Taxonomy_Mapping", "Taxonomy_Mapping", "Taxonomy_Mapping", cADict = ca, cSDict = ce)
        weakness.addCAPEC()
        weakness.addReferences()
        ca = {"Type":"Type"}
        weakness.addObjectFactWithAnnotation(LS + "Notes/" + LS + "Note", "Note", "Note", cADict = ca, note = True)
        weakness.addContentHystory()
        out_file.write(weakness.tostring())

def generateCategoryIndividual(item, out_file):
        weakness = Weakness(item)
        weakness.addType("Category")
        weakness.addType("Status")
        weakness.addDataFactFromAttribute("Name")
        weakness.addAnnotation("Summary")
        weakness.addMembers(relationships = True)
        ca = {"Taxonomy_Name":"Taxonomy_Name"}
        ce = {"Entry_ID":"Entry_ID", "Entry_Name":"Entry_Name", "Mapping_Fit":"Mapping_Fit"}
        weakness.addObjectFactWithAnnotation(LS + "Taxonomy_Mappings/" + LS + "Taxonomy_Mapping", "Taxonomy_Mapping", "Taxonomy_Mapping", cADict = ca, cSDict = ce)
        weakness.addReferences()
        ca = {"Type":"Type"}
        weakness.addObjectFactWithAnnotation(LS + "Notes/" + LS + "Note", "Note", "Note", cADict = ca, note = True)
        weakness.addContentHystory()
        out_file.write(weakness.tostring())

def generateViewIndividual(item, root, out_file):
        weakness = Weakness(item)
        weakness.addType("Type")
        weakness.addType("Status")
        weakness.addDataFactFromAttribute("Name")
        weakness.addAnnotation("Objective")
        weakness.addDataFactWithAnnotation("Type", "Description", path = LS + "Audience/" + LS + "Stakeholder/", name = "Audience", aName = "Audience_Description")
        weakness.addMembers()
        weakness.addAnnotation("Filter")
        f = item.find(LS + "Filter")
        if f is not None:
                n = int(item.attrib["ID"])
                if n == 1040:
                        for w in root.findall(LS + "Weaknesses/" + LS + "Weakness"):
                                for o in w.findall(LS + "Weakness_Ordinalities/" + LS + "Weakness_Ordinality/" + LS + "Ordinality"):
                                        if o.text == "Indirect":
                                                weakness.addContent(item.attrib["ID"], w.attrib["ID"])
                                                break
                elif n == 1081:
                        for e in root.findall("./*/*"):
                                for note in e.findall(LS + "Notes/" + LS + "Note"):
                                        if note.attrib["Type"] == "Maintenance":
                                                weakness.addContent(item.attrib["ID"], e.attrib["ID"])
                                                break
                elif n == 2000:
                        for e in root.findall(LS + "Weaknesses/*"):
                                weakness.addContent(item.attrib["ID"], e.attrib["ID"])
                        for e in root.findall(LS + "Categories/*"):
                                weakness.addContent(item.attrib["ID"], e.attrib["ID"])
                        for e in root.findall(LS + "Views/*"):
                                weakness.addContent(item.attrib["ID"], e.attrib["ID"])
                elif n == 604:
                        for e in root.findall("./*/*"):
                                if "Status" in e.attrib and e.attrib["Status"] == "Deprecated":
                                        weakness.addContent(item.attrib["ID"], e.attrib["ID"])
                elif n == 658:
                        for w in root.findall(LS + "Weaknesses/" + LS + "Weakness"):
                                for l in w.findall(LS + "Applicable_Platforms/" + LS + "Language"):
                                        if "Name" in l.attrib and l.attrib["Name"] == "C":
                                                weakness.addContent(item.attrib["ID"], w.attrib["ID"])
                                                break
                elif n == 659:
                        for w in root.findall(LS + "Weaknesses/" + LS + "Weakness"):
                                for l in w.findall(LS + "Applicable_Platforms/" + LS + "Language"):
                                        if "Name" in l.attrib and l.attrib["Name"] == "C++":
                                                weakness.addContent(item.attrib["ID"], w.attrib["ID"])
                                                break
                elif n == 660:
                        for w in root.findall(LS + "Weaknesses/" + LS + "Weakness"):
                                for l in w.findall(LS + "Applicable_Platforms/" + LS + "Language"):
                                        if "Name" in l.attrib and l.attrib["Name"] == "Java":
                                                weakness.addContent(item.attrib["ID"], w.attrib["ID"])
                                                break
                elif n == 661:
                        for w in root.findall(LS + "Weaknesses/" + LS + "Weakness"):
                                for l in w.findall(LS + "Applicable_Platforms/" + LS + "Language"):
                                        if "Name" in l.attrib and l.attrib["Name"] == "PHP":
                                                weakness.addContent(item.attrib["ID"], w.attrib["ID"])
                                                break
                if n == 677:
                        for w in root.findall(LS + "Weaknesses/" + LS + "Weakness"):
                                if w.attrib["Abstraction"] == "Base" and not w.attrib["Status"] == "Deprecated":
                                        weakness.addContent(item.attrib["ID"], w.attrib["ID"])
                if n == 678:
                        for w in root.findall(LS + "Weaknesses/" + LS + "Weakness"):
                                if w.attrib["Structure"] == "Composite" and not w.attrib["Status"] == "Deprecated":
                                        weakness.addContent(item.attrib["ID"], w.attrib["ID"])
                elif n == 701:
                        for w in root.findall(LS + "Weaknesses/" + LS + "Weakness"):
                                for p in w.findall(LS + "Modes_Of_Introduction/" + LS + "Introduction/" + LS + "Phase"):
                                        if p.text == "Architecture and Design":
                                                weakness.addContent(item.attrib["ID"], w.attrib["ID"])
                elif n == 702:
                        for w in root.findall(LS + "Weaknesses/" + LS + "Weakness"):
                                for p in w.findall(LS + "Modes_Of_Introduction/" + LS + "Introduction/" + LS + "Phase"):
                                        if p.text == "Implementation":
                                                weakness.addContent(item.attrib["ID"], w.attrib["ID"])
                                                break
                if n == 709:
                        for w in root.findall(LS + "Weaknesses/" + LS + "Weakness"):
                                if w.attrib["Structure"] == "Chain":
                                        weakness.addContent(item.attrib["ID"], w.attrib["ID"])
                elif n == 919:
                        for w in root.findall(LS + "Weaknesses/" + LS + "Weakness"):
                                for p in w.findall(LS + "Applicable_Platforms/" + LS + "Technology"):
                                        if "Class" in p.attrib and p.attrib["Class"] == "Mobile":
                                                weakness.addContent(item.attrib["ID"], w.attrib["ID"])
                                                break
                elif n == 999:
                        for w in root.findall(LS + "Weaknesses/" + LS + "Weakness"):
                                if w.attrib["Status"] == "Deprecated": continue
                                tm = w.find(LS + "Taxonomy_Mappings/")
                                if tm is None:
                                        weakness.addContent(item.attrib["ID"], w.attrib["ID"])
                                        continue
                                found = False
                                for t in tm.findall(LS + "Taxonomy_Mapping"):
                                        if t.attrib["Taxonomy_Name"] == "Software Fault Patterns":
                                                found = True
                                                break
                                if not found: weakness.addContent(item.attrib["ID"], w.attrib["ID"])
                        
        weakness.addReferences()
        ca = {"Type":"Type"}
        weakness.addObjectFactWithAnnotation(LS + "Notes/" + LS + "Note", "Note", "Note", cADict = ca, note = True)
        weakness.addContentHystory()
        out_file.write(weakness.tostring())

def generateIndividuals(root):

        def generateShell():

                def collectExternalReferences():
                        print("Generate external references")
                        externalreferences = root.find(LS + "External_References")
                        if externalreferences is not None:
                                r = ""
                                for e in externalreferences.findall(LS + "External_Reference"):
                                        r += "\n\tExternal_Reference \""
                                        for a in e.findall(LS + "Author"):
                                                r += "\nAuthor: " + code(a.text)
                                        r += "\nTitle: " + code(e.find(LS + "Title").text)
                                        ed = e.find(LS + "Edition")
                                        if ed is not None: r += "\nEdition: " + code(ed.text)
                                        p = e.find(LS + "Publication")
                                        if p is not None: r += "\nPublication: " + code(p.text)
                                        p = e.find(LS + "Publication_Year")
                                        if p is not None: r += "\nPublication year: " + code(p.text)
                                        p = e.find(LS + "Publication_Month")
                                        if p is not None: r += "\nPublication month: " + code(p.text)
                                        p = e.find(LS + "Publication_Day")
                                        if p is not None: r += "\nPublication day: " + code(p.text)
                                        p = e.find(LS + "Publisher")
                                        if p is not None: r += "\nPublisher: " + code(p.text)
                                        url = e.find(LS + "URL")
                                        if url is not None: r += "\nURL: " + code(url.text)
                                        url = e.find(LS + "URL_Date")
                                        if url is not None: r += "\nURL date: " + code(url.text)
                                        r += "\"^^rdfs:Literal,"
                                return r

                views = root.find(LS + "Views")
                for item in views.findall(LS + "View"):
                        view = "cwe-" + item.attrib["ID"]
                        out_file.write("Prefix: " + view + ": <http://www.semanticweb.org/cht_c/" + view + "#>\r")
                with open("shell.owl", mode='r', encoding='utf-8') as in_file:
                        shell = in_file.read()
                        name = root.attrib["Name"]
                        name = "" if name is None else name
                        shell = shell.replace("NAME", name)
                        version = root.attrib["Version"]
                        version = "" if version is None else version
                        shell = shell.replace("VERSION", version)
                        date = root.attrib["Date"]
                        date = "" if date is None else date
                        shell = shell.replace("DATE", date)
                        shell = shell.replace("External_Reference \"\"^^rdfs:Literal,", collectExternalReferences())
                        out_file.write(shell)
                for item in views.findall(LS + "View"):
                        view = "cwe-" + item.attrib["ID"] + ":"
                        out_file.write("\nObjectProperty: " + view + "Has_Member\n\tSubPropertyOf:\r\t\tHas_Member\n\tInverseOf:\n\t\t" + view + "Member_Of")
                        out_file.write("\nObjectProperty: " + view + "Member_Of\n\tSubPropertyOf:\r\t\tMember_Of\n\tInverseOf:\n\t\t" + view + "Has_Member")
                        out_file.write("\nObjectProperty: " + view + "ChildOf\n\tSubPropertyOf:\r\t\tChildOf\n\tInverseOf:\n\t\t" + view + "ParentOf")
                        out_file.write("\nObjectProperty: " + view + "ChildOf-Primary\n\tSubPropertyOf:\r\t\t" + view + "ChildOf\n\tInverseOf:\n\t\t" + view + "ParentOf-Primary")
                        out_file.write("\nObjectProperty: " + view + "ParentOf\n\tSubPropertyOf:\r\t\tParentOf\n\tInverseOf:\n\t\t" + view + "ChildOf")
                        out_file.write("\nObjectProperty: " + view + "ParentOf-Primary\n\tSubPropertyOf:\r\t\t" + view + "ParentOf\n\tInverseOf:\n\t\t" + view + "ChildOf-Primary")
                        if item.attrib["ID"] == "709":
                                out_file.write("\nObjectProperty: " + view + "StartsWith\n\tSubPropertyOf:\r\t\tStartsWith")
                                out_file.write("\nObjectProperty: " + view + "StartsWith-Primary\n\tSubPropertyOf:\r\t\t" + view + "StartsWith")
                                out_file.write("\nObjectProperty: " + view + "StartOfChain\n\tSubPropertyOf:\r\t\tStartOfChain")
                                out_file.write("\nObjectProperty: " + view + "StartStartOfChain-Primary\n\tSubPropertyOf:\r\t\t" + view + "StartOfChain")
                                out_file.write("\nObjectProperty: " + view + "CanFollow\n\tSubPropertyOf:\r\t\tCanFollow\n\tCharacteristics:\n\t\tFunctional\n\tInverseOf:\n\t\t" + view + "CanPrecede")
                                out_file.write("\nObjectProperty: " + view + "CanFollow-Primary\n\tSubPropertyOf:\r\t\t" + view + "CanFollow\n\tCharacteristics:\n\t\tFunctional\n\tInverseOf:\n\t\t" + view + "CanPrecede-Primary")
                                out_file.write("\nObjectProperty: " + view + "CanPrecede\n\tSubPropertyOf:\r\t\tCanPrecede\n\tCharacteristics:\n\t\tFunctional\n\tInverseOf:\n\t\t" + view + "CanFollow")
                                out_file.write("\nObjectProperty: " + view + "CanPrecede-Primary\n\tSubPropertyOf:\r\t\t" + view + "CanPrecede\n\tCharacteristics:\n\t\tFunctional\n\tInverseOf:\n\t\t" + view + "CanFollow-Primary")
                        else:
                                out_file.write("\nObjectProperty: " + view + "CanFollow\n\tSubPropertyOf:\r\t\tCanFollow\n\tInverseOf:\n\t\t" + view + "CanPrecede")
                                out_file.write("\nObjectProperty: " + view + "CanFollow-Primary\n\tSubPropertyOf:\r\t\t" + view + "CanFollow\n\tInverseOf:\n\t\t" + view + "CanPrecede-Primary")
                                out_file.write("\nObjectProperty: " + view + "CanPrecede\n\tSubPropertyOf:\r\t\tCanPrecede\n\tInverseOf:\n\t\t" + view + "CanFollow")
                                out_file.write("\nObjectProperty: " + view + "CanPrecede-Primary\n\tSubPropertyOf:\r\t\t" + view + "CanPrecede\n\tInverseOf:\n\t\t" + view + "CanFollow-Primary")
                        out_file.write("\nObjectProperty: " + view + "RequiredBy\n\tSubPropertyOf:\r\t\tRequiredBy\n\tInverseOf:\n\t\t" + view + "Requires")
                        out_file.write("\nObjectProperty: " + view + "RequiredBy-Primary\n\tSubPropertyOf:\r\t\t" + view + "RequiredBy\n\tInverseOf:\n\t\t" + view + "Requires-Primary")
                        out_file.write("\nObjectProperty: " + view + "Requires\n\tSubPropertyOf:\r\t\tRequires\n\tInverseOf:\n\t\t" + view + "RequiredBy")
                        out_file.write("\nObjectProperty: " + view + "Requires-Primary\n\tSubPropertyOf:\r\t\t" + view + "Requires\n\tInverseOf:\n\t\t" + view + "RequiredBy-Primary")
                        out_file.write("\nObjectProperty: " + view + "CanAlsoBe\n\tSubPropertyOf:\r\t\tCanAlsoBe")
                        out_file.write("\nObjectProperty: " + view + "CanAlsoBe-Primary\n\tSubPropertyOf:\r\t\t" + view + "CanAlsoBe")
                        out_file.write("\nObjectProperty: " + view + "PeerOf\n\tSubPropertyOf:\r\t\tPeerOf")
                        out_file.write("\nObjectProperty: " + view + "PeerOf-Primary\n\tSubPropertyOf:\r\t\t" + view + "PeerOf")                                                         
                out_file.write("\n")
                
        print("Processing started")
        fn = "results/cwe.owl"
        out_file = open(fn, mode='w', encoding='utf-8')
        generateShell()

        print("Generate weaknesses")
        weaknesses = root.find(LS + "Weaknesses")
        for item in weaknesses.findall(LS + "Weakness"):
                print("CWE-" + item.attrib["ID"])
                generateWeaknessIndividual(item, out_file)
                
        print("Generate categories")
        categories = root.find(LS + "Categories")
        for item in categories.findall(LS + "Category"):
                print("CWE-" + item.attrib["ID"])
                generateCategoryIndividual(item, out_file)
                
        print("Generate views")
        views = root.find(LS + "Views")
        for item in views.findall(LS + "View"):
                print("CWE-" + item.attrib["ID"])
                generateViewIndividual(item, root, out_file)
                
        for i in Individual.extend:
                out_file.write(i.tostring())

        out_file.close()
        print("Processing finished")

def main(download):
        print("CWE Ontology Generator, Version 5.3")
        start = datetime.now()
        print(start)
        if download:
                print("Download CWE List")
                downloadCWE()
        xml_file = lxml.etree.parse("data/cwec.xml")
        xml_validator = lxml.etree.XMLSchema(file="data/cwe_schema_latest.xsd")
        if not xml_validator.validate(xml_file):
                print("CWE List contents is not valid!")
                print(xml_validator.error_log)
                return
        xml_file = None
        xml_validator = None
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
