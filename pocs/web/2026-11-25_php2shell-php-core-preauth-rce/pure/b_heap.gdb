set pagination off
set confirm off
python
import gdb

def u64(inf, a):
    return int.from_bytes(inf.read_memory(a, 8).tobytes(), 'little')

def u32(inf, a):
    return int.from_bytes(inf.read_memory(a, 4).tobytes(), 'little')

def heap(inf):
    ag = int(gdb.parse_and_eval('&alloc_globals')) & 0xffffffffffffffff
    return u64(inf, ag)

def fp(inf):
    h = heap(inf)
    m = h & ~0x1fffff
    rsize = u64(inf, h + 0x118)
    free_pages = u32(inf, m + 0x18)
    free_tail = u32(inf, m + 0x1c)
    return "heap=%#x main=%#x fp=%d ftail=%d rsize=%#x" % (h, m, free_pages, free_tail, rsize)

def map_base(inf, chunk):
    for off in range(0x40, 0x400, 4):
        try:
            if u32(inf, chunk + off) == 0x40000001:
                return chunk + off
        except Exception:
            break
    return 0

def page_owner(inf, pnum):
    h = heap(inf)
    m = h & ~0x1fffff
    mb = map_base(inf, m)
    if not mb:
        return "nomap"
    info = u32(inf, mb + pnum * 4)
    if info & 0x80000000:
        bin_num = info & 0x1f
        try:
            head = u64(inf, h + 0x28 + bin_num * 8)
        except Exception:
            head = 0
        return "SRUN bin=%d head=%#x" % (bin_num, head)
    if info & 0x40000000:
        return "LRUN pages=%d" % (info & 0x3ff)
    return "FRUN"

class P(gdb.Breakpoint):
    def __init__(self, name, tag):
        super().__init__(name, internal=True)
        self.tag = tag
    def stop(self):
        try:
            inf = gdb.selected_inferior()
            extra = ""
            if self.tag == "CB":
                try:
                    ev = int(gdb.parse_and_eval('$rdi')) & 0xffffffffffffffff
                    extra = " event=%d" % ev
                except Exception:
                    pass
            print("%s %s page86=[%s]%s" % (self.tag, fp(inf), page_owner(inf, 0x56), extra), flush=True)
        except Exception as e:
            print(self.tag, "ERR", repr(e), flush=True)
        return False

for name, tag in [
    ("php_request_startup", "STARTUP"),
    ("php_hash_environment", "HASHENV"),
    ("php_auto_globals_create_post", "POSTGLOB"),
    ("rfc1867_post_handler", "RFC1867"),
    ("php_session_rfc1867_callback", "CB"),
    ("php_session_initialize", "SESSINIT"),
]:
    try:
        P(name, tag)
    except Exception as e:
        print("BPFAIL", name, repr(e), flush=True)
end
continue
