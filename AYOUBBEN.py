import sys
import zipfile
from androguard.core.bytecodes.arsc import ARSCParser

def extract_strings(apk_path, output_txt):
    # open APK as ZIP and read resources.arsc
    with zipfile.ZipFile(apk_path, "r") as apk:
        try:
            data = apk.read("resources.arsc")
        except KeyError:
            print("No resources.arsc in APK")
            return

    arsc = ARSCParser(data)

    with open(output_txt, "w", encoding="utf-8") as out:
        count = 0
        # iterate every package, type, entry
        for pkg in arsc.get_packages_names():
            # list all string resource IDs
            for res_id in arsc.get_res_ids():
                name = arsc.get_resource_xml_name(res_id)
                if not name:
                    continue
                # get default configuration value
                for config, entry in arsc.get_res_configs(res_id):
                    if entry is None:
                        continue
                    val = entry.get_value()
                    out.write(f"{name} = {val}\n")
                    count += 1
                    break  # only default locale
    print(f"Extracted {count} strings to {output_txt}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python extract_strings.py <APK_PATH> <OUTPUT.TXT>")
    else:
        extract_strings(sys.argv[1], sys.argv[2])
