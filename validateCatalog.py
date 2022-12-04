import lxml.etree
xml_file = lxml.etree.parse("data/cwec.xml")
xml_validator = lxml.etree.XMLSchema(file="data/cwe_schema_latest.xsd")

is_valid = xml_validator.validate(xml_file)

print(is_valid)  
