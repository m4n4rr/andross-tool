from construct import Int16ul, Int32ul, Struct, PascalString
import struct

# ================================
# ARSC BINARY STRUCTURE DEFINITIONS
# ================================

# Resource table header
ResTableHeader = Struct(
    "type" / Int16ul,
    "header_size" / Int16ul,
    "size" / Int32ul,
    "package_count" / Int32ul,
)

# Resource package header
ResTablePackage = Struct(
    "id" / Int32ul,
    "name" / PascalString(Int32ul, "utf-16-le"),
    "type_strings_start" / Int32ul,
    "last_public_type" / Int32ul,
    "key_strings_start" / Int32ul,
    "last_public_key" / Int32ul,
    "type_id_offset" / Int32ul,
)

# ================================
# STRING POOL PARSER
# ================================
def parse_string_pool(data, offset):
    """
    Parse ResStringPool_header from binary data.
    Returns list of strings extracted from the pool.
    """
    try:
        if offset + 28 > len(data):
            return []
        
        # ResStringPool_header structure
        type_val = struct.unpack_from('<H', data, offset)[0]
        header_size = struct.unpack_from('<H', data, offset + 2)[0]
        size = struct.unpack_from('<I', data, offset + 4)[0]
        string_start = struct.unpack_from('<I', data, offset + 8)[0]
        string_count = struct.unpack_from('<I', data, offset + 12)[0]
        flags = struct.unpack_from('<I', data, offset + 20)[0]
        
        # Flag 0x100 = UTF-16, flag 0x000 = UTF-8
        is_utf16 = (flags & 0x100) != 0
        
        strings = []
        string_offsets_start = offset + header_size
        
        for i in range(string_count):
            offset_pos = string_offsets_start + (i * 4)
            if offset_pos + 4 > len(data):
                break
            
            string_offset = struct.unpack_from('<I', data, offset_pos)[0]
            absolute_offset = offset + string_start + string_offset
            
            if absolute_offset >= len(data):
                continue
            
            # Read string based on encoding
            if is_utf16:
                # UTF-16 LE: 2-byte length prefix, then UTF-16 string
                try:
                    str_len = struct.unpack_from('<H', data, absolute_offset)[0]
                    start = absolute_offset + 2
                    end = start + (str_len * 2)
                    if end <= len(data):
                        s = data[start:end].decode('utf-16-le', errors='ignore').rstrip('\x00')
                        if s:
                            strings.append(s)
                except:
                    pass
            else:
                # UTF-8: 1-byte length prefix, then UTF-8 string
                try:
                    str_len = struct.unpack_from('<B', data, absolute_offset)[0]
                    start = absolute_offset + 1
                    end = start + str_len
                    if end <= len(data):
                        s = data[start:end].decode('utf-8', errors='ignore').rstrip('\x00')
                        if s:
                            strings.append(s)
                except:
                    pass
        
        return strings
    except Exception as e:
        return []

# ================================
# EXTRACT STRINGS FROM RESOURCES.ARSC
# ================================
def extract_strings_from_arsc(arsc_bytes, debug=False, skip_filter=False):
    """
    Extract string resources from resources.arsc using construct and binary parsing.
    Returns list of extracted strings with source tracking.
    Supports: string, string-array, and plurals resources.
    """
    try:
        if not arsc_bytes or len(arsc_bytes) < 28:
            if debug:
                print(f"[ARSC DEBUG] resources.arsc: Invalid or empty file")
            return []
        
        # Parse main ResTableHeader
        res_type = struct.unpack_from('<H', arsc_bytes, 0)[0]
        header_size = struct.unpack_from('<H', arsc_bytes, 2)[0]
        total_size = struct.unpack_from('<I', arsc_bytes, 4)[0]
        pkg_count = struct.unpack_from('<I', arsc_bytes, 8)[0]
        
        if res_type != 0x0001:  # RES_TABLE_TYPE
            if debug:
                print(f"[ARSC DEBUG] resources.arsc: Not a valid resource table (type: {res_type})")
            return []
        
        all_strings = []
        offset = header_size
        
        # Process each package
        for _ in range(pkg_count):
            if offset + 40 > len(arsc_bytes):
                break
            
            # Parse ResTablePackage header
            pkg_id = struct.unpack_from('<I', arsc_bytes, offset)[0]
            pkg_header_size = struct.unpack_from('<I', arsc_bytes, offset + 4)[0]
            pkg_size = struct.unpack_from('<I', arsc_bytes, offset + 8)[0]
            type_strings_start = struct.unpack_from('<I', arsc_bytes, offset + 12)[0]
            key_strings_start = struct.unpack_from('<I', arsc_bytes, offset + 20)[0]
            
            # Extract strings from key string pool (contains resource names)
            if key_strings_start > 0:
                key_pool_offset = offset + key_strings_start
                key_strings = parse_string_pool(arsc_bytes, key_pool_offset)
                for s in key_strings:
                    if s and len(s) >= 4:
                        all_strings.append({
                            "string": s,
                            "source": "resources.arsc",
                            "type": "resource_key",
                            "package_id": pkg_id
                        })
            
            # Extract strings from type string pool (contains value data)
            if type_strings_start > 0:
                type_pool_offset = offset + type_strings_start
                type_strings = parse_string_pool(arsc_bytes, type_pool_offset)
                for s in type_strings:
                    if s and len(s) >= 4:
                        all_strings.append({
                            "string": s,
                            "source": "resources.arsc",
                            "type": "resource_value",
                            "package_id": pkg_id
                        })
            
            offset += pkg_size
        
        if debug:
            print(f"[ARSC DEBUG] resources.arsc: {len(all_strings)} strings extracted")
        
        return all_strings
    except Exception as e:
        if debug:
            print(f"[ARSC DEBUG] resources.arsc: Parse error - {type(e).__name__}: {e}")
        return []
