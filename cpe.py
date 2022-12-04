from language_tags import tags
import re 

class CPE:
    
    def __init__(self, part="ANY", vendor="ANY", product="ANY", version="ANY", update="ANY", edition="ANY", language="ANY", \
                 sw_edition="ANY", target_sw="ANY", target_hw="ANY", other="ANY"):
        assert _isAvstring(part) and part in {'h', 'o', 'a', "ANY", "NA"}, "Bad part value: " + part
        assert _isAvstring(vendor), "vendor must be avstring: " + vendor
        assert _isAvstring(product), "product must be avstring: " + product
        assert _isAvstring(version), "version must be avstring: " + version
        assert _isAvstring(update), "update must be avstring: " + update
        assert _isAvstring(edition), "edition must be avstring: " + edition
        assert _isAvstring(language) and (language in {"ANY", "NA"} or tags.check(language.replace("\\", ""))), "Bad language value: " + language
        assert _isAvstring(sw_edition), "sw_edition must be avstring: " + sw_edition
        assert _isAvstring(target_sw), "target_sw must be avstring: " + target_sw
        assert _isAvstring(target_hw), "target_hw must be avstring: " + target_hw
        assert _isAvstring(other), "other must be avstring: " + other
        self.part = part
        self.vendor = vendor
        self.product = product
        self.version = version
        self.update = update
        self.edition = edition
        self.language = language
        self.sw_edition = sw_edition
        self.target_sw = target_sw
        self.target_hw = target_hw
        self.other = other

    def bind_to_uri(self):
        #Top-level function used to bind a WFN (CPE) to a URI.
        #Initialize the output with the CPE v2.2 URI prefix.
        #Call the pack() helper function to compute the proper binding for the edition element.
        #Get the value for a in w, then bind to a string for inclusion in the URI.
        #Append values to the URI then add a colon.
        #Return the URI string, with trailing colons trimmed.
        
        return ("cpe:/" + _bind_value_for_uri(self.part) + ":" + _bind_value_for_uri(self.vendor) + ":" + _bind_value_for_uri(self.product) + ":" + _bind_value_for_uri(self.version) + ":" + _bind_value_for_uri(self.update) + ":" + \
        _pack(_bind_value_for_uri(self.edition), _bind_value_for_uri(self.sw_edition), _bind_value_for_uri(self.target_sw), _bind_value_for_uri(self.target_hw), _bind_value_for_uri(self.other)) + ":" + \
        _bind_value_for_uri(self.language)).rstrip(":")
        #Remove trailing colons from the URI back to the first non-colon.

    def bind_to_fs(self):
        #Top-level function used to bind WFN (CPE) to formatted string.
        
        #Initialize the output with the CPE v2.3 string prefix.
        #Add a colon except at the very end.
        return "cpe:2.3:" + _bind_value_for_fs(self.part) + ":" + _bind_value_for_fs(self.vendor) + ":" + \
               _bind_value_for_fs(self.product) + ":" + _bind_value_for_fs(self.version) + ":" + _bind_value_for_fs(self.update) + ":" + \
               _bind_value_for_fs(self.edition) + ":" + _bind_value_for_fs(self.language) + ":" + \
               _bind_value_for_fs(self.sw_edition) + ":" + _bind_value_for_fs(self. target_sw) + ":" + \
               _bind_value_for_fs(self.target_hw) + ":" + _bind_value_for_fs(self.other) 
        
def _bind_value_for_fs(v):
    #Convert the value v to its proper string representation for insertion into the formatted string.
    if v == "ANY": return "*"
    if v == "NA": return "-"
    return _process_quoted_chars(v)

def _process_quoted_chars(s):
    #Inspect each character in string s.
    #Certain nonalpha characters pass thru without escaping into the result, but most retain escaping.

    text = s.replace("\\.", ".")
    text = text.replace("\\-", "-")
    return text.replace("\\_", "_")
    
def _isAvstring(s):
    if not isinstance(s, str): return False
    if s == "ANY" or s == "NA": return True
    dash = "[-]"
    spec1 = "[?]"
    spec2 = "[*]"
    punc_no_dash = r'[!"#$%&\'()+,./:;<=>@[\]^`{}~]'
    punc_w_dash = "(" + punc_no_dash + "|" + dash + ")"
    special = "(" + spec1 + "|" + spec2 + ")"
    escape = r"[\\]"
    quoted2 = "(" + escape + "(" + escape + "|" + special + "|" + punc_w_dash + ")" + ")"
    quoted1 = "(" + escape + "(" + escape + "|" + special + "|" + punc_no_dash + ")" + ")"
    unreserved = "[a-zA-Z0-9_]"
    body2 = "(" + unreserved + "|" + quoted2 + ")"
    body1 = "(" + unreserved + "|" + quoted1 + ")"
    body = "(" + "(" + body1 + body2 + "*" + ")" + "|" + body2 + "{2,}" + ")"
    spec_chrs = "(" + spec1 + "+" + "|" + spec2 + ")"
    avstring = "(" + body + "|" + "(" + spec_chrs + body2 + "*" + "))" + spec_chrs + "?"
    return True if re.match(avstring, s) else False

def _pack(ed, sw_ed, t_sw, t_hw, oth):
    #“Pack” the values of the five arguments into the single edition component. If all the values are blank, just return a blank.

    #All the extended attributes are blank, so don’t do any packing, just return ed.
    if sw_ed == "*" and t_sw == "*" and t_hw == "*" and oth == "*": return ed
    #Otherwise, pack the five values into a single string prefixed and internally delimited with the tilde.
    return '~' + ed + '~' + sw_ed + '~' + t_sw + '~' + t_hw + '~' + oth

def _bind_value_for_uri(s):
    #Takes a string s and converts it to the proper string for inclusion in a CPE v2.2-conformant URI.

    #The logical value ANY binds to the blank in the 2.2-conformant URI.
    if s == "ANY": return "*"
    #The value NA binds to a single hyphen.
    if s == "NA": return "-"
    #If we get here, we’re dealing with a string value.
    return _transform_for_uri(s)

def _transform_for_uri(s):
    #Scans an input string s and applies the following transformations:
    #- Pass alphanumeric characters thru untouched
    #- Percent-encode quoted non-alphanumerics as needed
    #- Unquoted special characters are mapped to their special forms.
    
    #Return the appropriate percent-encoding of the characters. Certain characters are returned without encoding.
    pct_encode = {'\\!':"%21", '\\"':"%22", '\\#':"%23", '\\$':"%24", '\\%':"%25", '\\&':"%26", "\\'":"%27", '\\(':"%28", '\\)':"%29", '\\*':"%2a", \
        '\\+':"%2b", '\\,':"%2c", '\\-':"-", '\\.':".", '\\/':"%2f", '\\:':"%3a", '\\;':"%3b", '\\<':"%3c", '\\=':"%3d", '\\>':"%3e", '\\?':"%3f", \
        '\\@':"%40", '\\[':"%5b", '\\\\':"%5c", '\\]':"%5d", '\\^':"%5e", '\\`':"%60", '\\{':"%7b", '\\|':"%7c", '\\}':"%7d", '\\~':"%7e"}
    #Alphanumerics (incl. underscore) pass untouched. Escaped characters are encoded.
    uri = s
    for key in pct_encode.keys():
        uri = uri.replace(key, pct_encode[key])
    #Bind the unquoted '?' special character to "%01".
    uri = uri.replace("?", "%01")
    #Bind the unquoted '*' special character to "%02"
    uri = uri.replace("*", "%02")
    return uri

def _isCPE_URI(uri):
    if not isinstance(uri, str): return False
    pct_encoded = "(%21" + "|" + "%22" + "|" + "%23" + "|" + "%24" + "|" + "%25" + "|" + "%26" + "|" + "%27" + "|" + \
        "%28" + "|" + "%29" + "|" + "%2a" + "|" + "%2b" + "|" + "%2c" + "|" + "%2f" + "|" + "%3a" + "|" + \
        "%3b" + "|" + "%3c" + "|" + "%3d" + "|" + "%3e" + "|" + "%3f" + "|" + "%40" + "|" + "%5b" + "|" + \
        "%5c" + "|" + "%5d" + "|" + "%5e" + "|" + "%60" + "|" + "%7b" + "|" + "%7c" + "|" + "%7d" + "|" + "%7e)"
    spec1 = "%01"
    spec2 = "%02"
    unreserved = "[-._a-zA-Z0-9]"
    spec_chrs = "(" + spec1 + "+|" + spec2  + ")"
    str_w_special = "((" + spec_chrs + ")?" + "(" + unreserved + "|" + pct_encoded + ")+" + spec_chrs + "?)"
    str_wo_special = "(" + unreserved + "|" + pct_encoded + ")*"
    string = "(" + str_wo_special + "|" + str_w_special + ")"
    lang = "[A-Za-z]{2,3}(-([A-Za-z]{2}|[0-9]{3}))?"
    vendor = string
    product = string
    version = string
    update = string
    packed = "(~" + string + "~" + string + "~" + string + "~" + string + "~" + string + ")"
    edition = "(" + string + "|" + packed + ")"
    part = "([hoa])?"
    component_list = "(((((" + part + "(:" + vendor + ")?)(:" + product + ")?)(:" + version + ")?)(:" + update + ")?)(:" + edition + ")?)(:" + lang + ")?"
    cpe_name = "cpe:/" + component_list
    return True if re.match(cpe_name, uri) else False

def unbind_uri(uri):
    #Top-level function used to unbind a URI uri to a WFN. Initialize the empty WFN (CPE).

    assert _isCPE_URI, "Bad CPE URI."

    #Get the components of uri and unbind the parsed string.
    s = uri.replace("\\:", chr(1))
    no = s.count(":")
    if no < 7:
        for i in range(7 - no):
            s += ":"
    cpe, part, vendor, product, version, update, edition, language = s.split(":")
    part = part[1:]
    vendor = _decode(vendor.replace(chr(1), "\\:"))
    product = _decode(product.replace(chr(1), "\\:"))
    version = _decode(version.replace(chr(1), "\\:"))
    update = _decode(update.replace(chr(1), "\\:"))
    #Special handling for edition component. Unpack edition if needed.
    edition = edition.replace(chr(1), "\\:")
    if (edition == "" or edition == "-" or "~" not in edition):
        #Just a logical value or a non-packed value. So unbind to legacy edition, leaving other extended attributes unspecified.
        edition = _decode(edition)
        sw_edition = target_sw = target_hw = other = "ANY"
    else:
        #We have five values packed together here.
        edition = edition.replace("\\~", chr(1))
        no = edition.count("~")
        if no < 5:
            for i in range(5 - no):
                edition += "~"    
        empty, edition, sw_edition, target_sw, target_hw, other = edition.split("~")
        edition = _decode(edition.replace(chr(1), "\\~"))
        sw_edition = _decode(sw_edition.replace(chr(1), "\\~"))
        target_sw = _decode(target_sw.replace(chr(1), "\\~"))
        target_hw = _decode(target_hw.replace(chr(1), "\\~"))
        other = _decode(other)
    language = _decode(language.replace(chr(1), "\\:"))
    return CPE(part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other)

def _decode(s):
    #This function scans the string s and returns a copy with all percent-encoded characters decoded.
    #This function is the inverse of pct_encode(s) defined in Section 6.1.2.3.
    #Only legal percent-encoded forms are decoded. Others raise an error.

    #Decode a blank to logical ANY, and hyphen to logical NA.
    if s == '*' or s == "": return "ANY"
    if s == '-': return "NA"

    #Start the scanning loop.
    #Normalize: convert all uppercase letters to lowercase first.
    pct_decode = {"%01":"?", "%02":"*", "%21":'\\!', "%22":'\\"', "%23":'\\#', "%24":'\\$', "%25":'\\%', "%26":'\\&', "%27":"\\'", "%28":'\\(', "%29":'\\)', \
        "%2a":'\\*', "%2b":'\\+', "%2c":'\\,', "-":'\\-', ".":'\\.', "%2f":'\\/', "%3a":'\\:', "%3b":'\\;', "%3c":'\\<', "%3d":'\\=', "%3e":'\\>', \
        "%3f":'\\?', "%40":'\\@', "%5b":'\\[', "%5c":'\\\\', "%5d":'\\]', "%5e":'\\^', "%60":'\\`', "%7b":'\\{', "%7c":'\\|', "%7d":'\\}', "%7e":'\\~'}
    text = s
    for key in pct_decode.keys():
        text = text.replace(key, pct_decode[key])
    return text

def _isFS(fs):
    if not isinstance(fs, str): return False
    escape = r"[\\]"
    punc = r"[!\"#$%&'()+,/:;<=>@[\]^`{}~]"
    special = r"[?*]"
    quoted = "(" + escape + "(" + escape + "|" + special + "|" + punc + "))"
    unreserved = r"[-._a-z0-9]"
    spec_chrs = r"(\?+|\*)"
    logical = "[-*]"
    avstring = "(" + spec_chrs + "?(" + unreserved + "|" + quoted + ")+" + spec_chrs + "?)|" + logical
    lang = r"(([a-z]{2,3}(-([a-z]{2}|[0-9]{3}))?)|" + logical + ")"
    vendor = product = version = update = edition = sw_edition = target_sw = target_hw = other = "(" + avstring + ")"
    part = "([hoa]|" + logical + ")"
    component_list = part + ":" + vendor + ":" + product + ":" + version + ":" + update + ":" + \
                     edition + ":" + lang + ":" + sw_edition + ":" + target_sw + ":" + target_hw + ":" + other
    formstring = r"cpe:2\.3:" + component_list
    return True if re.match(formstring, fs) else False
   
def unbind_fs(fs):
    #Top-level function to unbind a formatted string fs to a wfn (CPE).
    
    assert _isFS(fs), "Bad formated string."

    #NB: the cpe scheme is the 0th component, the cpe version is the 1st. So we start parsing at the 2nd component.
    parts = []
    for p in fs.replace("\\:", chr(1)).split(":"):
        parts.append(p.replace(chr(1), "\\:"))
    cpe, cpeVersion, part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other = parts
    part = _unbind_value_fs(part)
    vendor = _unbind_value_fs(vendor)
    product = _unbind_value_fs(product)
    version = _unbind_value_fs(version)
    update = _unbind_value_fs(update)
    edition = _unbind_value_fs(edition)
    language = _unbind_value_fs(language)
    sw_edition = _unbind_value_fs(sw_edition)
    target_sw = _unbind_value_fs(target_sw)
    target_hw = _unbind_value_fs(target_hw)
    other = _unbind_value_fs(other)
    return CPE(part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other)

def _unbind_value_fs(s):
    #Takes a string value s and returns the appropriate logical value if s is the bound form of a logical value.
    #If s is some general value string, add quoting of non-alphanumerics as needed.

    if s == "*": return "ANY"
    if s == "-": return "NA"
    
    #Add quoting to any unquoted non-alphanumeric characters, but leave the two special characters alone, as they may appear quoted or unquoted.
    return _add_quoting(s)

def _add_quoting(s):
    #Inspect each character in string s. Copy quoted characters, with their escaping, into the result.
    #Look for unquoted non alphanumerics and if not "*" or "?", add escaping.

    result = ""
    idx = 0
    while (idx < len(s)):
        c = s[idx]
        if c == "\\":
            #Anything quoted in the bound string stays quoted in the unbound string.
            result += s[idx: idx + 2]
            idx += 2
            continue
        
        #Alphanumeric characters pass untouched.
        
        #An unquoted asterisk must appear at the beginning or end of the string.
        #An unquoted question mark must appear at the beginning or end of the string, or in a leading or trailing sequence.
        #The FS is checked for that.

        if c.isalnum() or c == "_" or c == "*" or c == "?":
            result += c
            idx += 1
            continue

        #All other characters must be quoted.
        result += "\\" + c
        idx += 1
    return result

def convert_uri_to_fs(u):
    return unbind_uri(u).bind_to_fs()

def convert_fs_to_uri(fs):
    return unbind_fs(fs).bind_to_uri()

def convert_fs_to_compressed_uri(fs):
    r = convert_fs_to_uri(fs)
    #if lang is ":*" then remove it
    if r.endswith(":*"): r = r[:-2]
    #now process edition
    #mask escaped ~
    #they must be escaped in the FS components
    r = r.replace("\\~", chr(1))
    #remove the * in ~*~
    r = r.replace("~*~", "~~")
    r = r.replace("~*~", "~~")
    #if other is * remove it
    r = r.rstrip("*")
    #if edition is empty (:~~~~~) at the end then remove it
    if r.endswith(":~~~~~"): r = r[:-6]
    #restore escaped ~
    r = r.replace(chr(1), "\\~")
    #now process other components
    #first mask escaped :
    r = r.replace("\\:", chr(1))
    #remove * at the end
    r = r.rstrip("*")
    #remove the star at the beginning cpe/*:
    r = r.replace("cpe/*:", "cpe/:")
    #remove the * in :*:
    r = r.replace(":*:", "::")
    r = r.replace(":*:", "::")
    #now remove trailing :
    r = r.rstrip(":")
    #restore escaped : end return the string
    return r.replace(chr(1), "\\:")
