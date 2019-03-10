import re
import floss
import vivisect
from collections import namedtuple
from floss import strings
from floss import main

MAX_FILESIZE = 16*1024*1024
MIN_STRINGLEN = 4
ASCII_BYTE = " !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
String = namedtuple("String", ["s", "offset"])


def ascii_strings(buf, n=4):
    reg = "([%s]{%d,})" % (ASCII_BYTE, n)
    ascii_re = re.compile(reg)
    for match in ascii_re.finditer(buf):
        yield String(match.group().decode("ascii"), match.start())

def unicode_strings(buf, n=4):
    reg = b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
    uni_re = re.compile(reg)
    for match in uni_re.finditer(buf):
        try:
            yield String(match.group().decode("utf-16"), match.start())
        except UnicodeDecodeError:
            pass


def get_decoded_strings(exe):
    # type: (object) -> object
    # Prepare FLOSS for extracting hidden & encoded strings
    vw = vivisect.VivWorkspace()
    vw.loadFromFile(exe)
    vw.analyze()

    selected_functions = floss.main.select_functions(vw, None)
    decoding_functions_candidates = floss.identification_manager.identify_decoding_functions(
        vw,
        floss.main.get_all_plugins(),
        selected_functions
    )

    # Decode & extract hidden & encoded strings
    decoded_strings = floss.main.decode_strings(
        vw,
        decoding_functions_candidates,
        MIN_STRINGLEN
    )
    stack_strings = floss.stackstrings.extract_stackstrings(
        vw,
        selected_functions,
        MIN_STRINGLEN
    )

    # pprint(type(decoded_strings))

    stack_strings2 = list(stack_strings)

    decoded_strings2 = []

    for i in decoded_strings:
        decoded_strings2.append(i[1])

    for y in stack_strings2:
        decoded_strings2.append(y[1])

    return decoded_strings2


def get_strings(exe):

    string_list = []

    with open(exe, 'rb') as f:
        b = f.read()

    # s.offset
    for s in ascii_strings(b, n=4):
        string_list.append(s.s)

    for s in unicode_strings(b):
        string_list.append(s.s)


    decoded_strings = get_decoded_strings(exe)


    return string_list, decoded_strings

