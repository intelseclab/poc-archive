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

def heap(inf):
    ag = int(gdb.parse_and_eval('&alloc_globals')) & 0xffffffffffffffff
    return u64(inf, ag)

def map_base(inf, chunk):
    for off in range(0x40, 0x400, 4):
        try:
            if u32(inf, chunk + off) == 0x40000001:
                return chunk + off
        except Exception:
            break
    return 0

def page_info(inf, addr):
    if not addr:
        return "NULL"
    c = addr & ~0x1fffff
    p = (addr & 0x1fffff) >> 12
    try:
        chunk_heap = u64(inf, c)
        fp = u32(inf, c + 0x18)
        mb = map_base(inf, c)
        if not mb:
            return "addr=%#x chunk=%#x heap=%#x fp=%d map=?" % (addr, c, chunk_heap, fp)
        info = u32(inf, mb + p * 4)
        if info & 0x80000000:
            t = "SRUN bin=%d" % (info & 0x1f)
        elif info & 0x40000000:
            t = "LRUN pages=%d" % (info & 0x3ff)
        else:
            t = "FRUN"
        return "addr=%#x chunk=%#x heap=%#x fp=%d page=%#x map=%#x %s" % (
            addr, c, chunk_heap, fp, p, info, t)
    except Exception as e:
        return "addr=%#x ERR %r" % (addr, e)

def dump(inf):
    ps = int(gdb.parse_and_eval('&ps_globals')) & 0xffffffffffffffff
    pid = u64(inf, ps + PS_ID)
    md = u64(inf, ps + PS_MD)
    hsv = u64(inf, ps + PS_HSV)
    sc = u8(inf, ps + PS_SEND_COOKIE)
    st = u32(inf, ps + PS_STATUS)
    print("PS id=%#x status=%d send_cookie=%d md=%#x hsv=%#x" % (pid, st, sc, md, hsv), flush=True)
    if pid:
        try:
            print("  ID len=%d data0=%#x  [%s]" % (u64(inf, pid + 0x10), u8(inf, pid + 0x18), page_info(inf, pid)), flush=True)
        except Exception as e:
            print("  ID ERR", repr(e), flush=True)
    if md:
        try:
            lk = u64(inf, md); bd = u64(inf, md + 8); dd = u64(inf, md + 16)
            fd = u32(inf, md + 36)
            print("  MD last_key=%#x basedir=%#x dirdepth=%d fd=%d  [%s]" % (lk, bd, dd, fd, page_info(inf, md)), flush=True)
            if bd:
                print("  BASEDIR refcount=%#x type=%#x  [%s]" % (u32(inf, bd), u32(inf, bd + 4), page_info(inf, bd)), flush=True)
        except Exception as e:
            print("  MD ERR", repr(e), flush=True)
    h = heap(inf)
    mc = u64(inf, h + 0x140)
    rsize = u64(inf, h + 0x118)
    ncache = u32(inf, h + 0x148) if True else 0
    try:
        ncache = u64(inf, h + 0x148) & 0xffffffff
    except Exception:
        pass
    print("HEAP %#x main=%#x rsize=%#x main_fp=%d" % (h, mc, rsize, u32(inf, mc + 0x18)), flush=True)
    try:
        cc = u64(inf, h + 0x148)
        # cached_chunks is a pointer field; try both 0x148 (chunks_count) layout
    except Exception:
        pass

dump(gdb.selected_inferior())
end
continue
