set pagination off
set confirm off
python
import gdb

def u64(inf, a):
    return int.from_bytes(inf.read_memory(a, 8).tobytes(), 'little')

def u32(inf, a):
    return int.from_bytes(inf.read_memory(a, 4).tobytes(), 'little')

def dump():
    inf = gdb.selected_inferior()
    ag = int(gdb.parse_and_eval('&alloc_globals')) & 0xffffffffffffffff
    h = u64(inf, ag)
    chunk = h & ~0x1fffff
    fs4 = u64(inf, h + 0x48)
    print("DUMP heap=%#x chunk=%#x fs4=%#x" % (h, chunk, fs4), flush=True)
    q = fs4
    seq = []
    for _ in range(12):
        if not q:
            break
        seq.append(q)
        q = u64(inf, q)
    print("  fs4chain=" + " ".join("%#x" % x for x in seq), flush=True)
    base = chunk + 0x56000
    for slot in range(12):
        a = base + slot * 40
        try:
            b = inf.read_memory(a, 40).tobytes()
            rc = int.from_bytes(b[0:4], 'little')
            ti = int.from_bytes(b[4:8], 'little')
            hh = int.from_bytes(b[8:16], 'little')
            ln = int.from_bytes(b[16:24], 'little')
            dat = b[24:40]
            print("  slot%02d @%#x rc=%#x ti=%#x h=%#x len=%#x data=%s" % (
                slot, a, rc, ti, hh, ln, dat.hex()), flush=True)
        except Exception as e:
            print("  slot%02d ERR %r" % (slot, e), flush=True)

class B(gdb.Breakpoint):
    def __init__(self):
        super().__init__("php_session_rfc1867_callback", internal=True)
    def stop(self):
        try:
            ev = int(gdb.parse_and_eval('$rdi')) & 0xffffffffffffffff
            print("--- CB event=%d" % ev, flush=True)
        except Exception:
            pass
        dump()
        return False
B()
end
continue
