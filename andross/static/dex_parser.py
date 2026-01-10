import re
from androguard.core.dex import DEX
from .filters import is_useful_string
from ..utils.logger import error


def extract_coroutine_method_name(class_name, method_name):
    if method_name != "invokeSuspend":
        return method_name
    
    # Pattern: ClassName$functionName$number
    match = re.match(r".*\$([a-zA-Z_][a-zA-Z0-9_]*)\$\d+$", class_name)
    if match:
        original_name = match.group(1)
        return f"{original_name} (suspend)"
    
    return method_name


def extract_strings_from_dex_bytes(dex_bytes, dex_name):
    try:
        d = DEX(dex_bytes)
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
        error(f"DEX extraction failed ({dex_name}): {e}")
        return []
