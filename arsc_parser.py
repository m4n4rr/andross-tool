import struct

STRING_POOL_TYPE = 0x0001
UTF8_FLAG = 0x00000100

def parse_string_pool(data, offset, debug=False):
    try:
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
        if chunk_type != STRING_POOL_TYPE:
            return []

        string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
            "<IIIII", data, offset + 8
        )
        is_utf8 = bool(flags & UTF8_FLAG)
        offsets_base = offset + header_size
        strings_base = offset + strings_start

        strings = []
        for i in range(string_count):
            str_offset = struct.unpack_from("<I", data, offsets_base + i * 4)[0]
            pos = strings_base + str_offset

            if is_utf8:
                u16_len = data[pos]
                u8_len = data[pos + 1]
                pos += 2
                value = data[pos:pos + u8_len].decode("utf-8", errors="ignore")
            else:
                u16_len = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                value = data[pos:pos + u16_len * 2].decode("utf-16le", errors="ignore")

            if value:
                strings.append(value)
        return strings
    except Exception:
        return []

def is_printable_ascii(s):
    for c in s:
        if ord(c) < 32 or ord(c) > 126:
            return False
    return True

def extract_strings_from_arsc(data, debug=False, skip_filter=False):
    """
    data: bytes of resources.arsc
    Returns: list of dicts compatible with main() unique_strings
    """
    all_strings = []
    pools_found = 0

    for offset in range(0, len(data) - 8, 4):
        chunk_type = struct.unpack_from("<H", data, offset)[0]
        if chunk_type == STRING_POOL_TYPE:
            strings = parse_string_pool(data, offset, debug)
            if strings:
                pools_found += 1
                all_strings.extend(strings)

    if debug:
        print("\n[DEBUG] ===============================")
        print("[DEBUG] String pools found:", pools_found)
        print("[DEBUG] Total strings extracted:", len(all_strings))
        print("[DEBUG] resources.arsc parsing OK")
        print("[DEBUG] ===============================\n")

    output = []
    for s in all_strings:
        if skip_filter or is_printable_ascii(s):
            output.append({
                "string": s,
                "source": "resources.arsc",
            })

    return output
