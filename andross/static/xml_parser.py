import xml.etree.ElementTree as ET

from androguard.core.axml import AXMLPrinter

from .filters import is_useful_string

def axml_to_xml_string(axml_bytes):
    try:
        printer = AXMLPrinter(axml_bytes)
        return printer.get_xml_as_string()
    except Exception:
        return None

def extract_strings_from_xml_bytes(xml_bytes, xml_file_path, debug=False, skip_filter=False):
    try:
        # Try to parse as binary AXML first
        xml_string = axml_to_xml_string(xml_bytes)
        
        # If AXML conversion fails, try as plain text XML
        if xml_string is None:
            xml_string = xml_bytes.decode('utf-8', errors='ignore')
        
        root = ET.fromstring(xml_string)
        all_strings = []
        
        # Extract from <string> tags
        for string_elem in root.findall('.//string'):
            if string_elem.text:
                text = string_elem.text.strip()
                if skip_filter or is_useful_string(text):
                    all_strings.append({
                        "string": text,
                        "source": xml_file_path,
                        "type": "string_tag"
                    })
        
        # Extract from string-array items
        for string_array in root.findall('.//string-array'):
            for item in string_array.findall('item'):
                if item.text:
                    text = item.text.strip()
                    if skip_filter or is_useful_string(text):
                        all_strings.append({
                            "string": text,
                            "source": xml_file_path,
                            "type": "string_array_item"
                        })
        
        # Extract from plurals
        for plurals in root.findall('.//plurals'):
            for item in plurals.findall('item'):
                if item.text:
                    text = item.text.strip()
                    if skip_filter or is_useful_string(text):
                        all_strings.append({
                            "string": text,
                            "source": xml_file_path,
                            "type": "plurals_item"
                        })
        
        # Extract from string attributes
        for elem in root.iter():
            for attr_name in ['android:text', 'android:hint', 'android:label', 'android:description']:
                attr_value = elem.get(attr_name)
                if attr_value :
                    if skip_filter or is_useful_string(attr_value):
                        all_strings.append({
                            "string": attr_value,
                            "source": xml_file_path,
                            "type": f"attribute_{attr_name}"
                        })
        
        if debug and all_strings:
            print(f"[XML DEBUG] {xml_file_path}: {len(all_strings)} strings extracted")
        
        return all_strings
    except ET.ParseError:
        # Silent fail for non-string XML files (layouts, animators, etc.)
        return []
    except Exception as e:
        # Silent fail for unparseable files
        if debug:
            print(f"[XML DEBUG] {xml_file_path}: Parse error - {type(e).__name__}")
        return []
