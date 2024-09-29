import sys
from pathlib import Path
from functools import partial
from dataclasses import dataclass
from enum import Enum


DEBUG_FINDING_ENTRY = 1<<0
DEBUG_PARSING_BYTES = 1<<1
DEBUG_IDX_MAPS_GEN  = 1<<2
DEBUG = (
    #DEBUG_FINDING_ENTRY |
    #DEBUG_PARSING_BYTES |
    #DEBUG_IDX_MAPS_GEN |
    0 # Allow for trailing '|'
)


def log_debug(what: int, msg: str):
    if DEBUG & what:
        print(f"DEBUG: {msg}", file=sys.stderr)


def main():
    term_name = sys.argv[1]
    idx_to_cap_maps = gen_idx_to_cap_maps()
    term_info_entry_path = find_terminfo_entry(term_name)
    with open(term_info_entry_path, "rb") as f:
        term_info_entry_bytes = f.read()
    parse_result = parse_bytes(idx_to_cap_maps, term_info_entry_bytes)
    print(parse_result)


@dataclass
class IdxCapsMaps:
    bools_map: list[str]
    nums_map: list[str]
    str_map: list[str]


class CapStatus(Enum):
    PRESENT = 1
    ABSENT = -1
    CANCELED = -2


@dataclass
class BoolCap:
    name: str
    status: CapStatus
    value: bool


@dataclass
class NumCap:
    name: str
    status: CapStatus
    value: int


@dataclass
class StrCap:
    name: str
    status: CapStatus
    value: str


@dataclass
class ParseResult:
    term_names: list[str]
    bool_caps : list[BoolCap]
    num_caps  : list[NumCap]
    str_caps  : list[StrCap]


def parse_bytes(idx_to_cap_maps: IdxCapsMaps, bytes_: bytes) -> ParseResult:
    # See `man term(5)` for a description of the "legacy" and "extended"
    # terminfo entry formats https://man.archlinux.org/man/term.5#a)

    local_log_debug = partial(log_debug, DEBUG_PARSING_BYTES)

    result = ParseResult(term_names=[], bool_caps=[], num_caps=[], str_caps=[])
    idx = 0

    # Determine whether the entry uses extended number format format from the
    # magic number
    is_extended_num_fmt = False
    magic_num_legacy       = 0o432
    magic_num_extended_num = 0o1036
    magic_num = bytes_[idx] | bytes_[idx + 1]<<8
    if magic_num == magic_num_legacy:
        local_log_debug(f"Entry uses 16bit numbers")
        is_extended_num_fmt = False
    elif magic_num == magic_num_extended_num:
        local_log_debug(f"Entry uses 32bit numbers")
        is_extended_num_fmt = True
    else:
        raise Exception(
            f"Invalid magic number {oct(magic_num)}. "
            f"Expected either {oct(magic_num_legacy)} or {oct(magic_num_extended_num)}!")
    idx += 2

    # Parse entry header
    local_log_debug(f"Parsing header:")
    term_names_section_size = bytes_[idx] | bytes_[idx + 1]<<8
    local_log_debug(f"    Terminal names section size: {term_names_section_size}")
    idx += 2
    bools_count = bytes_[idx] | bytes_[idx + 1]<<8
    local_log_debug(f"    Number of boolean flags: {bools_count}")
    idx += 2
    nums_count = bytes_[idx] | bytes_[idx + 1]<<8
    local_log_debug(f"    Number of numbers: {nums_count}")
    idx += 2
    strs_count = bytes_[idx] | bytes_[idx + 1]<<8
    local_log_debug(f"    Number of strings: {strs_count}")
    idx += 2
    strs_table_size = bytes_[idx] | bytes_[idx + 1]<<8
    local_log_debug(f"    Strings table size: {strs_table_size}")
    idx += 2

    # Parse terminal name aliases
    term_names = bytes_[idx:idx + term_names_section_size - 1].decode("ascii").split("|")
    idx += term_names_section_size - 1
    local_log_debug(f"Terminal names: {', '.join(term_names)}")
    if bytes_[idx] != 0:
        raise Exception("Long terminal name was not terminated by 0!")
    idx += 1
    result.term_names = term_names

    # Parse boolean capabilities
    local_log_debug("Parsing boolean capabilities:")
    for bool_idx in range(bools_count):
        cap = idx_to_cap_maps.bools_map[bool_idx]
        if bytes_[idx] == 1:
            result.bool_caps.append(BoolCap(
                name=idx_to_cap_maps.bools_map[bool_idx],
                status=CapStatus.PRESENT,
                value=True,
            ))
            local_log_debug(f"    {cap}: true")
        elif bytes_[idx] == 0:
            result.bool_caps.append(BoolCap(
                name=idx_to_cap_maps.bools_map[bool_idx],
                status=CapStatus.ABSENT,
                value=False,
            ))
            local_log_debug(f"    {cap}: false")
        elif bytes_[idx] == 0o376:
            result.bool_caps.append(BoolCap(
                name=idx_to_cap_maps.bools_map[bool_idx],
                status=CapStatus.CANCELED,
                value=False,
            ))
            local_log_debug(f"    {cap}: canceled")
        else:
            raise Exception(f"Unexpected value {bytes_[idx]} for boolean flag '{cap}'")
        idx += 1
    bools_end_with_null_byte = (idx % 2) == 1 and bytes_[idx] == 0
    if bools_end_with_null_byte:
        local_log_debug("Skipping 0 byte for alignment after bools")
        idx += 1

    # Parse numeric capabilities
    local_log_debug("Parsing numeric capabilities:")
    for num_idx in range(nums_count):
        cap = idx_to_cap_maps.nums_map[num_idx]
        num = bytes_[idx] | bytes_[idx + 1]<<8
        if is_extended_num_fmt:
            num |= bytes_[idx + 2]<<16 | bytes_[idx + 3]<<24
            if num & 0x8000:
                num = -((~num & 0xFFFF) + 1) # 32bit two's complement
        else:
            if num & 0x80:
                num = -((~num & 0xFF) + 1) # 16bit two's complement
        if num == -1:
            result.num_caps.append(NumCap(
                name=idx_to_cap_maps.nums_map[num_idx],
                status=CapStatus.ABSENT,
                value=CapStatus.ABSENT.value,
            ))
            local_log_debug(f"    {cap}: absent")
        elif num == -2:
            result.num_caps.append(NumCap(
                name=idx_to_cap_maps.nums_map[num_idx],
                status=CapStatus.CANCELED,
                value=CapStatus.CANCELED.value,
            ))
            local_log_debug(f"    {cap}: canceled")
        else:
            result.num_caps.append(NumCap(
                name=idx_to_cap_maps.nums_map[num_idx],
                status=CapStatus.PRESENT,
                value=num,
            ))
            local_log_debug(f"    {cap}: {num}")
        idx += 2
        if is_extended_num_fmt:
            idx += 2

    # Parse string capabilities
    table_start = idx + strs_count*2
    local_log_debug("Parsing string capabilities:")
    for str_idx in range(strs_count):
        cap = idx_to_cap_maps.str_map[str_idx]
        table_offset = bytes_[idx] | bytes_[idx + 1]<<8
        if table_offset & 0x80:
            table_offset = -((~table_offset & 0xFF) + 1) # 16bit two's complement
        if table_offset == -1:
            result.str_caps.append(StrCap(
                name=idx_to_cap_maps.str_map[str_idx],
                status=CapStatus.ABSENT,
                value="",
            ))
            local_log_debug(f"    {cap}: absent")
        elif table_offset == -2:
            result.str_caps.append(StrCap(
                name=idx_to_cap_maps.str_map[str_idx],
                status=CapStatus.CANCELED,
                value="",
            ))
            local_log_debug(f"    {cap}: canceled")
        else:
            table_entry_start = table_start + (bytes_[idx] | bytes_[idx + 1]<<8)
            table_entry_stop = table_entry_start
            while bytes_[table_entry_stop] != 0:
                table_entry_stop += 1
            string = bytes_[table_entry_start:table_entry_stop].decode("ascii")
            result.str_caps.append(StrCap(
                name=idx_to_cap_maps.str_map[str_idx],
                status=CapStatus.PRESENT,
                value=string,
            ))
            local_log_debug(f"    {cap}: {repr(string)}")
        idx += 2

    return result


TERMINFO_DIRS = [
    "~/.terminfo",
    "/etc/terminfo",
    "/lib/terminfo",
    "/usr/share/terminfo",
]
def find_terminfo_entry(term_name):
    local_log_debug = partial(log_debug, DEBUG_FINDING_ENTRY)

    for dir_path_str in TERMINFO_DIRS:
        dir_path = Path(dir_path_str)
        if not dir_path.exists():
            local_log_debug(
                f"Terminfo dir={dir_path} does not exist, skipping")
            continue

        term_name_first_letter = term_name[0]
        term_entry_path = dir_path / term_name_first_letter / term_name
        if not term_entry_path.exists():
            local_log_debug(
                f"No terminfo entry={term_entry_path} in dir={dir_path}, skipping")
            continue

        local_log_debug(f"Found terminfo entry={term_entry_path} for {term_name}")
        return term_entry_path

    raise Exception(
        f"Failed to find terminfo entry for {term_name} in all terminfo dirs!")


TERM_C_HEADER_PATH = "./term_c_header_defines.txt"
def gen_idx_to_cap_maps() -> IdxCapsMaps:
    local_log_debug = partial(log_debug, DEBUG_IDX_MAPS_GEN)

    maps = IdxCapsMaps(bools_map=[], nums_map=[], str_map=[])

    file_path = Path(TERM_C_HEADER_PATH)
    if not file_path.exists():
        raise Exception(f"No C header file at {TERM_C_HEADER_PATH}!")

    with open(file_path, "r") as f:
        file_content = f.read()
    for line in file_content.splitlines():
        if not line.startswith("#define") or "CUR" not in line or (
            "Booleans[" not in line and
            "Numbers[" not in line and
            "Strings[" not in line
        ):
            continue
        local_log_debug(f"Extracting idx->cap mapping from line: {line}")
        cap = line.split(" ", 3)[1]
        local_log_debug(f"    terminal capability={cap}")
        idx = int(line[line.find("[") + 1:line.find("]")])
        local_log_debug(f"    index={idx}")
        map_: list[str]
        if "Booleans" in line:
            local_log_debug(f"    type=boolean flag")
            map_ = maps.bools_map
        elif "Numbers" in line:
            local_log_debug(f"    type=number")
            map_ = maps.nums_map
        elif "String" in line:
            local_log_debug(f"    type=string")
            map_ = maps.str_map
        else:
            raise Exception("Unexpected")
        if idx >= len(map_):
            map_ += [""]*(idx - len(map_) + 1)
        map_[idx] = cap

    return maps


main()

