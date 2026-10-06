"""테스트용 바이너리 픽스처 빌더 — AXML/DEX/APK/IPA를 코드로 생성한다."""
import plistlib
import struct
import zipfile

# ---------- AXML ----------

def _string_pool(strings, utf8=True):
    data = b""
    offsets = []
    for s in strings:
        offsets.append(len(data))
        if utf8:
            b = s.encode("utf-8")
            data += bytes([len(s) & 0x7F]) + bytes([len(b) & 0x7F]) + b + b"\x00"
        else:
            b = s.encode("utf-16-le")
            data += struct.pack("<H", len(s)) + b + b"\x00\x00"
    header_size = 28
    offsets_arr = b"".join(struct.pack("<I", o) for o in offsets)
    size = header_size + len(offsets_arr) + len(data)
    flags = 0x100 if utf8 else 0
    chunk = struct.pack("<HHIIIIII", 0x0001, header_size, size, len(strings), 0,
                        flags, header_size + len(offsets_arr), 0)
    return chunk + offsets_arr + data


def _start_element(name_idx, attrs):
    """attrs: list of (ns_idx, name_idx, raw_idx, vtype, vdata)"""
    attr_bytes = b""
    for a in attrs:
        attr_bytes += struct.pack("<III", a[0], a[1], a[2])
        attr_bytes += struct.pack("<HBBI", 8, 0, a[3], a[4])
    body = struct.pack("<IIHHHHHH", 0xFFFFFFFF, name_idx, 20, 20, len(attrs), 0, 0, 0)
    size = 16 + 20 + len(attr_bytes)
    return struct.pack("<HHIII", 0x0102, 16, size, 1, 0xFFFFFFFF) + body + attr_bytes


def _end_element(name_idx):
    return struct.pack("<HHIII", 0x0103, 16, 24, 1, 0xFFFFFFFF) + \
        struct.pack("<II", 0xFFFFFFFF, name_idx)


def _cdata(idx):
    """ResXMLTree_cdataExt: 헤더(16) + string ref(4) + Res_value(8) = 28바이트."""
    return struct.pack("<HHIII", 0x0104, 16, 28, 1, 0xFFFFFFFF) + \
        struct.pack("<I", idx) + struct.pack("<HBBI", 8, 0, 0x03, idx)


def build_axml(strings, chunks, utf8=True):
    pool = _string_pool(strings, utf8=utf8)
    body = b"".join(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(pool) + len(body)) + pool + body


def axml_document(tree):
    """tree: [(tag, {attr: str값}, [children]), ...] → AXML 바이트.

    속성은 전부 STRING 타입으로 인코딩한다(파서는 rawValue 우선 처리).
    children에 순수 str이 있으면 텍스트(CDATA) 노드로 인코딩한다.
    """
    strings = []

    def collect(tag, attrs, children):
        strings.append(tag)
        for k, v in attrs.items():
            strings.extend((k, str(v)))
        for child in children:
            if isinstance(child, str):
                strings.append(child)
            else:
                collect(*child)

    for node in tree:
        collect(*node)
    unique = list(dict.fromkeys(strings))
    idx = {s: i for i, s in enumerate(unique)}

    chunks = []

    def emit(tag, attrs, children):
        attr_items = [
            (0xFFFFFFFF, idx[k], idx[str(v)], 0x03, idx[str(v)])
            for k, v in attrs.items()
        ]
        chunks.append(_start_element(idx[tag], attr_items))
        for child in children:
            if isinstance(child, str):
                chunks.append(_cdata(idx[child]))
            else:
                emit(*child)
        chunks.append(_end_element(idx[tag]))

    for node in tree:
        emit(*node)
    return build_axml(unique, chunks)


# ---------- DEX ----------

def _uleb(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def build_dex(strings):
    ids_off = 0x70
    data = b""
    offsets = []
    for s in strings:
        offsets.append(ids_off + 4 * len(strings) + len(data))
        data += _uleb(len(s)) + s.encode("utf-8") + b"\x00"
    ids = b"".join(struct.pack("<I", o) for o in offsets)
    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x20, ids_off + 4 * len(strings) + len(data))
    struct.pack_into("<I", header, 0x24, 0x70)
    struct.pack_into("<I", header, 0x28, 0x12345678)
    struct.pack_into("<II", header, 0x38, len(strings), ids_off)
    return bytes(header) + ids + data


# ---------- APK / IPA ----------

def build_apk(path, axml_bytes, dex_strings=None, v1=True, extra=None):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", axml_bytes)
        if dex_strings is not None:
            z.writestr("classes.dex", build_dex(dex_strings))
        if v1:
            z.writestr("META-INF/CERT.RSA", b"\x30\x82\x00\x00")  # 존재만 확인
        for name, content in (extra or {}).items():
            z.writestr(name, content)


def add_v2_block(path):
    """빌드된 zip에 최소 APK Signing Block을 삽입하고 EOCD의 CD 오프셋을 보정한다."""
    with open(path, "rb") as f:
        data = bytearray(f.read())
    eocd = bytes(data).rfind(b"PK\x05\x06")
    (cd_off,) = struct.unpack_from("<I", data, eocd + 16)
    magic = b"APK Sig Block 42"
    block = struct.pack("<Q", 24) + struct.pack("<Q", 24) + magic
    data[cd_off:cd_off] = block
    struct.pack_into("<I", data, eocd + 16 + len(block), cd_off + len(block))
    with open(path, "wb") as f:
        f.write(bytes(data))


def build_ipa(path, plist_dict, binary=b"", provisioning=None):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("Payload/MyApp.app/Info.plist", plistlib.dumps(plist_dict))
        z.writestr("Payload/MyApp.app/MyApp", binary)
        if provisioning is not None:
            z.writestr("Payload/MyApp.app/embedded.mobileprovision", provisioning)


# ---------- 시나리오 픽스처 ----------

import contextlib
import os
import tempfile

from quaygate.apk import Apk


def manifest_tree(app_over=None, sdk_over=None, components=None, perms=None, root_over=None):
    app = {"allowBackup": "false", "debuggable": "false", "usesCleartextTraffic": "false"}
    app.update(app_over or {})
    app = {k: v for k, v in app.items() if v is not None}  # None은 '속성 제거'를 뜻한다
    sdk = {"minSdkVersion": "24", "targetSdkVersion": "34"}
    sdk.update(sdk_over or {})
    sdk = {k: v for k, v in sdk.items() if v is not None}
    root = {"package": "com.example", "versionName": "1.0"}
    root.update(root_over or {})
    root = {k: v for k, v in root.items() if v is not None}
    children = [("uses-sdk", sdk, [])]
    children += [("uses-permission", {"name": p}, []) for p in (perms or [])]
    children.append(("application", app, components or []))
    return [("manifest", root, children)]


@contextlib.contextmanager
def temp_apk(app_over=None, sdk_over=None, components=None, perms=None, dex=None, v1=True, v2=False,
             nsc=None, arsc_types=None, arsc_paths=None, files=None):
    fd, path = tempfile.mkstemp(suffix=".apk")
    os.close(fd)
    extra = {}
    if nsc is not None:
        extra["res/xml/network_security_config.xml"] = axml_document(nsc)
    if arsc_types is not None:
        extra["resources.arsc"] = build_arsc(arsc_types, paths=arsc_paths)
    extra.update(files or {})
    build_apk(path, axml_document(manifest_tree(app_over, sdk_over, components, perms)),
              dex_strings=dex, v1=v1, extra=extra or None)
    if v2:
        add_v2_block(path)
    try:
        yield path
    finally:
        os.unlink(path)


def make_plist(over=None):
    plist = {
        "CFBundleIdentifier": "com.example.app",
        "CFBundleShortVersionString": "1.0",
        "CFBundleExecutable": "MyApp",
        "MinimumOSVersion": "16.0",
    }
    plist.update(over or {})
    return plist


@contextlib.contextmanager
def temp_ipa(plist_over=None, binary=b"", provisioning=None):
    fd, path = tempfile.mkstemp(suffix=".ipa")
    os.close(fd)
    build_ipa(path, make_plist(plist_over), binary, provisioning=provisioning)
    try:
        yield path
    finally:
        os.unlink(path)


def build_fat64(cryptid=0, pie=True):
    """FAT64(0xCAFEBABF) fat_arch_64(32바이트) 헤더 + thin 슬라이스 1개."""
    flags = 0x00200000 if pie else 0
    thin = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 20, flags, 0)
    thin += struct.pack("<IIIII", 0x2C, 20, 0, 0, cryptid)
    header = struct.pack(">II", 0xCAFEBABF, 1)
    arch = struct.pack(">IIQQQ", 0x0100000C, 0, 8 + 32, len(thin), 14)  # fat_arch_64
    return header + arch + thin


def build_macho(cryptid=0, fat=False, pie=True, canary=True):
    """최소 Mach-O 바이너리(arm64, LC_ENCRYPTION_INFO_64 1개)."""
    flags = 0x00200000 if pie else 0
    thin = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 20, flags, 0)
    thin += struct.pack("<IIIII", 0x2C, 20, 0, 0, cryptid)
    if canary:
        thin += b"___stack_chk_fail\x00"
    if not fat:
        return thin
    fat_header = struct.pack(">II", 0xCAFEBABE, 1)
    arch = struct.pack(">IIIII", 0x0100000C, 0, 8 + 20, len(thin), 14)
    return fat_header + arch + thin


# ---------- resources.arsc ----------

def build_arsc(types, sparse=False, paths=None, compact=False, bool_true_refs=(), bool_false_refs=()):
    """단일 패키지(0x7F) 리소스 테이블. types: [(타입명, [엔트리명])].

    매핑 규칙: (0x7F<<24)|(type_id<<16)|entry_idx → 엔트리명, type_id는 1부터.
    sparse=True면 aapt2 sparse 인코딩(u16 idx/offset 쌍), compact=True면 compact
    엔트리(하위 0x08, bool 값)로 쓴다. bool_true_refs의 엔트리명은 true로 기록.
    paths={엔트리명: "res/xY.xml"}를 주면 엔트리 값(STRING)에 경로를 넣는다
    — 경로 난독화 APK 재현.
    """
    paths = dict(paths or {})
    type_names = [t for t, _ in types]
    keys = []
    per_type = []
    for _, entries in types:
        idxs = []
        for e in entries:
            if e not in keys:
                keys.append(e)
            idxs.append(keys.index(e))
        per_type.append(idxs)

    pathed = [e for _, entries in types for e in entries if e in paths]
    global_strings = [""] + [paths[e] for e in pathed]
    gidx = {e: i + 1 for i, e in enumerate(pathed)}
    global_pool = _string_pool(global_strings)

    type_pool = _string_pool(type_names)
    key_pool = _string_pool(keys)
    type_chunks = []
    for type_no, idxs in enumerate(per_type, start=1):
        count = len(idxs)
        config_size = 8
        header_size = 20 + config_size
        entries = b""
        offsets = b""
        for pos_i, key_idx in enumerate(idxs):
            entry_off = len(entries)
            if compact:
                # aapt2 compact — key u16, flags=(type<<8)|0x08, data u32
                entries += struct.pack("<HHI", key_idx, (0x12 << 8) | 0x08,
                                       1 if keys[key_idx] in bool_true_refs else 0)
            else:
                entries += struct.pack("<HHI", 8, 0, key_idx)
                if keys[key_idx] in bool_true_refs or keys[key_idx] in bool_false_refs:
                    # TYPE_INT_BOOLEAN — 참조 해석용 bool 값
                    entries += struct.pack("<HBBI", 8, 0, 0x12,
                                           1 if keys[key_idx] in bool_true_refs else 0)
                else:
                    entries += struct.pack("<HBBI", 8, 0, 0x03, gidx.get(keys[key_idx], 0))
            if sparse:
                offsets += struct.pack("<HH", pos_i, entry_off // 4)
            else:
                offsets += struct.pack("<I", entry_off)
        entries_start = header_size + 4 * count
        chunk = struct.pack("<HHI", 0x0201, header_size, entries_start + len(entries))
        chunk += bytes([type_no, 0x01 if sparse else 0x00]) + struct.pack("<H", 0)
        chunk += struct.pack("<II", count, entries_start)
        chunk += struct.pack("<I", config_size) + b"\x00" * (config_size - 4)
        type_chunks.append(chunk + offsets + entries)

    pkg_header = 288
    type_off = pkg_header
    key_off = type_off + len(type_pool)
    inner = type_pool + key_pool + b"".join(type_chunks)
    pkg_name = "com.example".encode("utf-16-le")
    pkg = struct.pack("<HHI", 0x0200, pkg_header, pkg_header + len(inner))
    pkg += struct.pack("<I", 0x7F)
    pkg += pkg_name + b"\x00" * (256 - len(pkg_name))
    pkg += struct.pack("<IIII", type_off, len(type_names), key_off, len(keys))
    pkg += b"\x00\x00\x00\x00"  # typeIdOffset(신형 헤더 288바이트 맞춤)
    pkg += inner
    table_size = 12 + len(global_pool) + len(pkg)
    return struct.pack("<HHII", 0x0002, 12, table_size, 1) + global_pool + pkg


# ---------- ELF ----------

def build_elf64(pie=True, execstack=False, relro="full", canary=True):
    """최소 ELF64 — PIE/NX/RELRO(BIND_NOW)/카나리 심볼 문자열."""
    e_type = 3 if pie else 2
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4], header[5], header[6] = 2, 1, 1  # 64비트, little-endian, version
    struct.pack_into("<H", header, 16, e_type)
    struct.pack_into("<H", header, 18, 0xB7)  # EM_AARCH64
    struct.pack_into("<H", header, 52, 64)    # ehsize
    struct.pack_into("<H", header, 54, 56)    # phentsize
    struct.pack_into("<Q", header, 32, 64)    # phoff

    dynamic = b""
    if relro == "full":
        dynamic += struct.pack("<QQ", 24, 1)  # DT_BINDNOW
    dynamic += struct.pack("<QQ", 0, 0)       # DT_NULL

    phdrs = b""
    dyn_off = 64  # phdr 영역 뒤에 배치(개수는 아래에서 확정 후 재계산)
    # phnum: LOAD + DYNAMIC + GNU_STACK (+ GNU_RELRO)
    phnum = 3 + (1 if relro != "none" else 0)
    dyn_off = 64 + 56 * phnum
    def phdr(p_type, flags, off, size):
        return struct.pack("<IIQQQQQQ", p_type, flags, off, 0, 0, size, size, 0x1000)
    phdrs += phdr(1, 6, dyn_off, len(dynamic))              # PT_LOAD RW
    phdrs += phdr(2, 6, dyn_off, len(dynamic))              # PT_DYNAMIC
    phdrs += phdr(0x6474E551, 7 if execstack else 6, 0, 0)  # PT_GNU_STACK
    if relro != "none":
        phdrs += phdr(0x6474E552, 4, dyn_off, len(dynamic))  # PT_GNU_RELRO
    struct.pack_into("<H", header, 56, phnum)
    tail = b"__stack_chk_fail\x00" if canary else b""
    return bytes(header) + phdrs + dynamic + tail


# ---------- 코드 포함 DEX ----------

def build_code_dex(calls):
    """호출 지점이 담긴 DEX. calls: [(호출클래스, 호출메서드, api클래스, api메서드, 인자문자열|None)]

    모든 호출을 단일 클래스의 개별 direct 메서드로 인코딩한다(호출 메서드명은 m0, m1, ...).
    타입 디스크립터는 'Lcom/t/Cls;' 형태. 레이아웃: 헤더·id표·클래스정의·class_data·코드·문자열.
    """
    strings = ["Ljava/lang/Object;", "V"]

    def intern(s):
        if s not in strings:
            strings.append(s)
        return strings.index(s)

    types = []

    def intern_type(desc):
        idx = intern(desc)
        if idx not in types:
            types.append(idx)
        return types.index(idx)

    obj_type = intern_type("Ljava/lang/Object;")
    protos = [(intern("V"), obj_type, 0)]

    method_specs = []   # (class_type_idx, proto_idx, name_idx)
    code_items = []     # (api_mid, string_idx|None)
    for i, (cls, _meth, api_cls, api_meth, arg) in enumerate(calls):
        cls_idx = intern_type(cls)
        api_idx = intern_type(api_cls)
        name_idx = intern(f"m{i}")
        method_specs.append((cls_idx, 0, name_idx))
        api_mid = len(method_specs)
        method_specs.append((api_idx, 0, intern(api_meth)))
        arg_idx = intern(arg) if arg is not None else None
        code_items.append((api_mid, arg_idx))

    def ulebs(values):
        return b"".join(_uleb(v) for v in values)

    def make_code(api_mid, arg_idx):
        insns = b""
        if arg_idx is not None:
            insns += struct.pack("<HH", (0 << 8) | 0x1A, arg_idx)  # const-string v0, s@arg
        insns += struct.pack("<HHH", (1 << 12) | 0x71, api_mid, 0x0000)  # invoke-static {v0}, m@api
        return struct.pack("<HHHHII", 4, 0, 2, 0, 0, len(insns) // 2) + insns

    ids_end = 0x70 + 4 * len(strings) + 4 * len(types) + 12 * len(protos) + 8 * len(method_specs)
    class_defs_off = ids_end
    class_data_off = class_defs_off + 32
    # class_data 길이는 code_off 값과 무관하게 일정 → 1회 더 만들어 크기 확정
    codes = [make_code(*item) for item in code_items]
    header_counts = (0, 0, len(code_items), 0)
    entries = []
    prev = 0
    for i in range(len(code_items)):
        mid = 2 * i
        entries.append((mid - prev, 0x9, 0))
        prev = mid
    class_data = ulebs(header_counts) + b"".join(ulebs(e) for e in entries)

    def rebuild_class_data(code_base):
        out = ulebs(header_counts)
        prev = 0
        for i in range(len(code_items)):
            mid = 2 * i
            out += ulebs((mid - prev, 0x9, code_base[i]))
            prev = mid
        return out

    # code_off가 커지면 uleb 길이가 늘어나 전체가 밀린다 — 고정점까지 반복
    for _ in range(16):
        code_base = []
        pos = class_data_off + len(class_data)
        for c in codes:
            code_base.append(pos)
            pos += len(c)
        rebuilt = rebuild_class_data(code_base)
        stable = len(rebuilt) == len(class_data)
        class_data = rebuilt  # 길이가 같아도 오프셋 값은 갱신 필요
        if stable:
            break
    strings_off = class_data_off + len(class_data) + sum(len(c) for c in codes)

    string_data = b""
    string_offsets = []
    for s in strings:
        string_offsets.append(strings_off + len(string_data))
        string_data += _uleb(len(s)) + s.encode("utf-8") + b"\x00"

    total = strings_off + len(string_data)
    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x20, total)
    struct.pack_into("<I", header, 0x24, 0x70)
    struct.pack_into("<I", header, 0x28, 0x12345678)
    struct.pack_into("<II", header, 0x38, len(strings), 0x70)
    struct.pack_into("<II", header, 0x40, len(types), 0x70 + 4 * len(strings))
    struct.pack_into("<II", header, 0x48, len(protos), 0x70 + 4 * len(strings) + 4 * len(types))
    struct.pack_into("<II", header, 0x58, len(method_specs),
                     0x70 + 4 * len(strings) + 4 * len(types) + 12 * len(protos))
    struct.pack_into("<II", header, 0x60, 1, class_defs_off)

    out = bytes(header)
    out += b"".join(struct.pack("<I", o) for o in string_offsets)
    out += b"".join(struct.pack("<I", t) for t in types)
    out += b"".join(struct.pack("<III", *p) for p in protos)
    out += b"".join(struct.pack("<HHI", *m) for m in method_specs)
    out += struct.pack("<IIIIIIII", method_specs[0][0], 1, obj_type, 0,
                       0xFFFFFFFF, 0, class_data_off, 0)
    out += class_data
    out += b"".join(codes)
    out += string_data
    return out
