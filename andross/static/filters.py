# ================================
# STRING FILTER
# ================================
def is_useful_string(s):
    if not s or len(s) < 4:
        return False
    for c in s:
        if ord(c) < 32 or ord(c) > 126:
            return False
    if s.startswith(("Lkotlin", "Ljava", "Landroid", "Lcom", "[Ljava", "[Lkotlin", "[Landroid", "[Lcom")):
        return False
    return True
