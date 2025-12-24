import re
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from filters import is_useful_string

# ================================
# EXTRACT COROUTINE METHOD NAMES
# ================================
def extract_coroutine_method_name(class_name, method_name):
    """
    Maps invokeSuspend methods back to original Kotlin suspend function names.
    Pattern: OuterClass$functionName$*
    Example: MyClass$checkForUpdates$1 -> checkForUpdates (suspend)
    """
    if method_name != "invokeSuspend":
        return method_name
    
    # Pattern: ClassName$functionName$number
    match = re.match(r".*\$([a-zA-Z_][a-zA-Z0-9_]*)\$\d+$", class_name)
    if match:
        original_name = match.group(1)
        return f"{original_name} (suspend)"
    
    return method_name

# ================================
# EXTRACT STRINGS FROM DEX IN MEMORY
# ================================
def extract_strings_from_dex_bytes(dex_bytes, dex_name):
    try:
        d = dvm.DalvikVMFormat(dex_bytes)
        x = analysis.Analysis(d)
        all_strings = []

        for cls in d.get_classes():
            class_name = cls.get_name()
            for method in cls.get_methods():
                code = method.get_code()
                if not code:
                    continue
                for instruction in code.get_bc().get_instructions():
                    op_value = instruction.get_name()
                    if "const-string" in op_value:
                        s = instruction.get_string()
                        if is_useful_string(s):
                            method_name = method.get_name()
                            # Map coroutine suspend functions
                            mapped_method_name = extract_coroutine_method_name(class_name, method_name)
                            all_strings.append({
                                "string": s,
                                "dex": dex_name,
                                "class": class_name,
                                "method": mapped_method_name
                            })
        return all_strings
    except Exception as e:
        print(f"[ERROR] DEX extraction failed ({dex_name}): {e}")
        return []
