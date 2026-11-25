set pagination off
set confirm off
python
import gdb

PS_ID = 0x10
PS_MD = 0x60
PS_HSV = 0x168
PS_SEND_COOKIE = 0x15e
PS_STATUS = 0x68

def u64(inf, a):
    return int.from_bytes(inf.read_memory(a, 8).tobytes(), 'little')

def u32(inf, a):
    return int.from_bytes(inf.read_memory(a, 4).tobytes(), 'little')

def u8(inf, a):
    return int.from_bytes(inf.read_memory(a, 1).tobytes(), 'little')

def ps_addr():
    return int(gdb.parse_and_eval('&ps_globals')) & 0xffffffffffffffff

def heap_addr(inf):
    ag = int(gdb.parse_and_eval('&alloc_globals')) & 0xffffffffffffffff
    return u64(inf, ag)

def map_base(inf, chunk):
    # chunk header page: find the 512-entry page map by its distinctive
    # map[0] == ZEND_MM_LRUN(1) == 0x40000001 after a request shutdown.
    for off in range(0x40, 0x400, 4):
        try:
            if u32(inf, chunk + off) == 0x40000001:
                return chunk + off
        except Exception:
            break
    return 0


def page_desc(inf, addr):
    if not addr:
        return "NULL"
    try:
        c = addr & ~0x1fffff
        pnum = (addr & 0x1fffff) >> 12
        mb = map_base(inf, c)
        info = u32(inf, mb + pnum * 4) if mb else 0
        if info & 0x80000000:
            t = "SRUN bin=%d" % (info & 0x1f)
        elif info & 0x40000000:
            t = "LRUN pages=%d" % (info & 0x3ff)
        else:
            t = "FRUN"
        return "addr=%#x chunk=%#x cheapptr=%#x page=%#x map=%#x %s" % (
            addr, c, u64(inf, c), pnum, info, t)
    except Exception as e:
        return "addr=%#x ERR %r" % (addr, e)

def chunk_info(inf, heap):
    chunk = heap & ~0x1fffff
    out = []
    c = chunk
    total = 0
    for _ in range(120):
        fp = u32(inf, c + 0x18)
        total += fp
        out.append(fp)
        nxt = u64(inf, c + 0x08)
        if not nxt or nxt == chunk:
            break
        c = nxt
    return chunk, total, out

def flen(inf, head, limit=6000):
    n = 0
    q = head
    seen = set()
    while q and n < limit and q not in seen:
        seen.add(q)
        nxt = u64(inf, q)
        if nxt == q:
            break
        q = nxt
        n += 1
    return n

def md_str(inf, md):
    if not md:
        return " md=NULL"
    try:
        lk = u64(inf, md)
        bd = u64(inf, md + 8)
        dd = u64(inf, md + 16)
        ss = u64(inf, md + 24)
        fm = u32(inf, md + 32)
        fd = u32(inf, md + 36)
        return " md=%#x mdpage=%#x last_key=%#x basedir=%#x dd=%d st=%#x fm=%d fd=%d" % (
            md, (md & 0x1fffff) >> 12, lk, bd, dd, ss, fm, fd)
    except Exception as e:
        return " md=%#x <ERR %r>" % (md, e)

def ps_dump(inf, tag):
    ps = ps_addr()
    pid = u64(inf, ps + PS_ID)
    md = u64(inf, ps + PS_MD)
    hsv = u64(inf, ps + PS_HSV)
    sc = u8(inf, ps + PS_SEND_COOKIE)
    st = u32(inf, ps + PS_STATUS)
    s = "%s ps=%#x id=%#x status=%d send_cookie=%d hsv=%#x%s" % (
        tag, ps, pid, st, sc, hsv, md_str(inf, md))
    if md:
        try:
            bd = u64(inf, md + 8)
            s += "\n  BASEDIR %s refcount=%#x type=%#x" % (
                page_desc(inf, bd), u32(inf, bd) if bd else 0, u32(inf, bd + 4) if bd else 0)
        except Exception as e:
            s += "\n  BASEDIRERR %r" % (e,)
    if pid:
        try:
            ln = u64(inf, pid + 0x10)
            b0 = u8(inf, pid + 0x18)
            s += " idlen=%d id0=%#x idpage=%#x idoff=%#x" % (
                ln, b0, (pid & 0x1fffff) >> 12, pid & 0x1fffff)
        except Exception as e:
            s += " <idERR %r>" % (e,)
    return s

class URLB(gdb.Breakpoint):
    def __init__(self):
        super().__init__("php_url_encode", internal=True)
    def stop(self):
        try:
            inf = gdb.selected_inferior()
            rdi = int(gdb.parse_and_eval('$rdi')) & 0xffffffffffffffff
            rsi = int(gdb.parse_and_eval('$rsi')) & 0xffffffffffffffff
            heap = heap_addr(inf)
            rsize = u64(inf, heap + 0x118)
            limit = u64(inf, heap + 0x128)
            fs128 = u64(inf, heap + 0x80)
            chunk, total, chain = chunk_info(inf, heap)
            fs4 = u64(inf, heap + 0x28 + 4 * 8)
            fs32 = u64(inf, heap + 0x28 + 3 * 8)
            print("URL rdi=%#x len=%d heap=%#x chunk=%#x fs128=%#x fs128len=%d fs4=%#x fs4len=%d fs32=%#x fs32len=%d rsize=%#x limit=%#x fp=%d chain=%s" % (
                rdi, rsi, heap, chunk, fs128, flen(inf, fs128), fs4, flen(inf, fs4),
                fs32, flen(inf, fs32), rsize, limit, total, chain[:8]), flush=True)
            print(ps_dump(inf, "URLPS"), flush=True)
            try:
                print("  pre=%s" % inf.read_memory(rdi - 0x38, 0x78).tobytes().hex(), flush=True)
            except Exception:
                pass
        except Exception as e:
            print("URLERR", repr(e), flush=True)
        return False
URLB()

class INITB(gdb.Breakpoint):
    def __init__(self):
        super().__init__("php_session_initialize", internal=True)
    def stop(self):
        try:
            inf = gdb.selected_inferior()
            h = heap_addr(inf)
            fs4 = u64(inf, h + 0x28 + 4 * 8)
            fs32 = u64(inf, h + 0x28 + 3 * 8)
            print("SESSINIT fs4=%#x len=%d fs32=%#x len=%d" % (fs4, flen(inf, fs4), fs32, flen(inf, fs32)), flush=True)
            print(ps_dump(inf, "SESSINIT"), flush=True)
        except Exception as e:
            print("INITERR", repr(e), flush=True)
        return False
INITB()

class CLOSEB(gdb.Breakpoint):
    def __init__(self):
        super().__init__("ps_close_files", internal=True)
    def stop(self):
        try:
            inf = gdb.selected_inferior()
            mdv = int(gdb.parse_and_eval('$rdi')) & 0xffffffffffffffff
            md = u64(inf, mdv) if mdv else 0
            heap = heap_addr(inf)
            chunk, total, chain = chunk_info(inf, heap)
            print("CLOSE mod_data_slot=%#x md=%#x heap=%#x chunk=%#x fp=%d%s" % (
                mdv, md, heap, chunk, total, md_str(inf, md)), flush=True)
            try:
                mp = map_base(inf, chunk)
                pnum = (md & 0x1fffff) >> 12
                mv = u32(inf, mp + pnum * 4) if mp else 0
                bd = u64(inf, md + 8) if md else 0
                print("  BASEDIR %s" % page_desc(inf, bd), flush=True)
                print("  mdpage=%#x mapoff=%#x mdmap=%#x mdpage_bytes=%s" % (
                    pnum, mp - chunk if mp else 0, mv,
                    inf.read_memory(md & ~0xfff, 0x100).tobytes().hex()), flush=True)
            except Exception as e:
                print("  pageERR", repr(e), flush=True)
        except Exception as e:
            print("CLOSEERR", repr(e), flush=True)
        return False
CLOSEB()

class BAILB(gdb.Breakpoint):
    def __init__(self):
        super().__init__("_zend_bailout", internal=True)
    def stop(self):
        try:
            inf = gdb.selected_inferior()
            h = heap_addr(inf)
            chunk, total, chain = chunk_info(inf, h)
            print("BAILOUTHEAP rsize=%#x limit=%#x fp=%d chain=%s" % (
                u64(inf, h + 0x118), u64(inf, h + 0x128), total, chain[:10]), flush=True)
            print(ps_dump(inf, "BAILOUT"), flush=True)
            print(gdb.execute("bt 8", to_string=True), flush=True)
        except Exception as e:
            print("BAILERR", repr(e), flush=True)
        return False
BAILB()

class ABORTB(gdb.Breakpoint):
    def __init__(self):
        super().__init__("abort", internal=True)
    def stop(self):
        try:
            print("ABORT_CALL", flush=True)
            print(gdb.execute("bt 10", to_string=True), flush=True)
        except Exception:
            pass
        return False
ABORTB()

class FORCEB(gdb.Breakpoint):
    def __init__(self):
        super().__init__("php_session_rfc1867_callback", internal=True)
    def stop(self):
        try:
            ev = int(gdb.parse_and_eval('$rdi')) & 0xffffffffffffffff
            if ev == 5:
                inf = gdb.selected_inferior()
                h = heap_addr(inf)
                ps = ps_addr()
                md = u64(inf, ps + PS_MD)
                old = u64(inf, h + 0x48)
                inf.write_memory(h + 0x48, md.to_bytes(8, 'little'))
                print("FORCE fs4 %#x -> %#x (md=%#x)" % (old, md, md), flush=True)
        except Exception as e:
            print("FORCEERR", repr(e), flush=True)
        return False
FORCEB()
end
handle SIGSEGV stop print nopass
continue
