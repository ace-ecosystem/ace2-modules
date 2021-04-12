# vim: ts=4:sw=4:et:cc=120

import os.path

from ace.analysis import RootAnalysis, FileObservable, Analysis
from ace.module.base import AnalysisModule
from ace.logging import get_logger


# known file extensions for microsoft office files
# see https://en.wikipedia.org/wiki/List_of_Microsoft_Office_filename_extensions
# 2/19/2018 - removed MSO file ext (relying on OLE format instead)
# 6/29/2018 - https://docs.google.com/spreadsheets/d/1LXneVF8VxmOgkt2W_NG5Kl3lzWW45prE7gxtuPcO-4o/edit#gid=1950593040
KNOWN_OFFICE_EXTENSIONS = [
    ".{}".format(ext)
    for ext in [
        # Microsoft Word
        "doc",
        "docb",
        "dochtml",
        "docm",
        "docx",
        "docxml",
        "dot",
        "dothtml",
        "dotm",
        "dotx",
        "odt",
        "rtf",
        "wbk",
        "wiz",
        # Microsoft Excel
        "csv",
        "dqy",
        "iqy",
        "odc",
        "ods",
        "slk",
        "xla",
        "xlam",
        "xlk",
        "xll",
        "xlm",
        "xls",
        "xlsb",
        "xlshtml",
        "xlsm",
        "xlsx",
        "xlt",
        "xlthtml",
        "xltm",
        "xltx",
        "xlw",
        # Microsoft Powerpoint
        "odp",
        "pot",
        "pothtml",
        "potm",
        "potx",
        "ppa",
        "ppam",
        "pps",
        "ppsm",
        "ppsx",
        "ppt",
        "ppthtml",
        "pptm",
        "pptx",
        "pptxml",
        "pwz",
        "sldm",
        "sldx",
        "thmx",
        # OpenOffice
        "odt",
    ]
]

#'mso',
#'ppt', 'pot', 'pps', 'pptx', 'pptm', 'potx', 'potm', 'ppam', 'ppsx', 'ppsm', 'sldx', 'sldm', 'rtf', 'pub' ]]

# same thing for macros extracted from office documents
KNOWN_MACRO_EXTENSIONS = [".bas", ".frm", ".cls"]


def is_office_ext(path):
    """Returns True if the given path has a file extension that would be opened by microsoft office."""
    root, ext = os.path.splitext(path)
    return ext in KNOWN_OFFICE_EXTENSIONS


def is_office_file(_file):
    """Returns True if we think this is probably an Office file of some kind."""
    assert isinstance(_file, Observable) and _file.type == F_FILE
    result = is_office_ext(os.path.basename(_file.value))
    file_type_analysis = _file.get_analysis(FileTypeAnalysis)
    if not file_type_analysis:
        return result

    result |= "microsoft powerpoint" in file_type_analysis.file_type.lower()
    result |= "microsoft excel" in file_type_analysis.file_type.lower()
    result |= "microsoft word" in file_type_analysis.file_type.lower()
    result |= "microsoft ooxml" in file_type_analysis.file_type.lower()
    result |= "opendocument" in file_type_analysis.file_type.lower()
    return result


def is_macro_ext(path):
    root, ext = os.path.splitext(path)
    return ext in KNOWN_MACRO_EXTENSIONS


def is_ole_file(path):
    with open(path, "rb") as fp:
        return fp.read(8) == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"


def is_rtf_file(path):
    with open(path, "rb") as fp:
        data = fp.read(4)
        return data[:3] == b"\\rt" or data == b"{\\rt"


def is_pdf_file(path):
    with open(path, "rb") as fp:
        return b"%PDF-" in fp.read(1024)


def is_pe_file(path):
    with open(path, "rb") as fp:
        return fp.read(2) == b"MZ"


def is_zip_file(path):
    with open(path, "rb") as fp:
        return fp.read(2) == b"PK"


def is_empty_macro(path):
    """Returns True if the given macro file only has empty lines and/or Attribute settings."""
    with open(path, "rb") as fp:
        for line in fp:
            # if the line is empty keep moving
            if line.strip() == b"":
                continue

            # or if it starts with one of these lines
            if line.startswith(b"Attribute VB_"):
                continue

            # otherwise it's something else, so return False
            return False

    return True


def _safe_filename(s):
    def _safe_char(c):
        # we want . for file ext and / for dir path, but ...
        if c.isalnum() or c == "/" or c == ".":
            return c
        else:
            return "_"

    # make sure we don't allow parent dir
    return ("".join(_safe_char(c) for c in s).rstrip("_")).replace(
        "..", "_"
    )  # turn parent dir into bemused face


def disassemble(path, offset, first_instr_offset, match_len, context_bytes, decoder):
    """
    Try to disassemble the context_bytes provided so that an instruction starts on the first byte of the yara match (first_instr_offset)
    Typically asm signatures should land this way.
    """
    rtn = None
    for off in range(0, first_instr_offset):
        instructions = distorm3.Decode(offset + off, context_bytes[off:], decoder)
        for instr in instructions:
            # If one of the instructions aligns with the first byte of the signature match, then our alignment is probably correct. Return result
            if instr[0] == first_instr_offset:
                return render_disassembly(
                    instructions, offset + first_instr_offset, match_len
                )
    # We failed to align an instruction with the signature match. Just disassemble from the start of context
    logging.debug(
        "Failed to align disassembly with context: {} first byte offset: 0x{}".format(
            binascii.hexlify(context_bytes), first_instr_offset
        )
    )
    return render_disassembly(
        distorm3.Decode(offset, context_bytes, decoder),
        offset + first_instr_offset,
        match_len,
    )


def render_disassembly(dis, match_offset, match_len, context_lines=4):
    """
    Accepts a DecodeGenerator from distorm and returns a string that will be directly rendered in the ICE yara results page
    dis: DecodeGenerator from distorm.Decode()
    match_offset: offset into the file where the match occured
    match_len: Length of yara  match
    context_lines: How many lines of disassembly to return before and after the matching lines
    """
    lines = []
    first_line = None
    last_line = None
    for i in range(len(dis)):
        instr = dis[i]
        asm = "0x{:08X}     {:<20}{}".format(instr[0], instr[3], instr[2])
        if instr[0] >= match_offset and instr[0] < match_offset + match_len:
            lines.append("<b>{}</b>".format(asm))
            if not first_line:
                first_line = i
        else:
            lines.append(asm)
            if first_line and not last_line:
                last_line = i
    lines = (
        lines[:first_line][-context_lines - 1 :]
        + lines[first_line:last_line]
        + lines[last_line:][:context_lines]
    )
    logging.error("Rendered disassembly: {}".format("\n".join(lines)))
    return "\n".join(lines)
