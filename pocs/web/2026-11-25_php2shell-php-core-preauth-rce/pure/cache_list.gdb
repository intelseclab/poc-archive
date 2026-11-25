set pagination off
set confirm off
python
import gdb

def u64(inf, a):
    return int.from_bytes(inf.read_memory(a, 8).tobytes(), 'little')

def u32(inf, a):
    return int.from_bytes(inf.read_memory(a, 4).tobytes(), 'little')

inf = gdb.selected_inferior()
ps = int(gdb.parse_and_eval('&ps_globals')) & 0xffffffffffffffff
pid = u64(inf, ps + 0x10)
md = u64(inf, ps + 0x60)
bd = u64(inf, md + 8) if md else 0
sc = int.from_bytes(inf.read_memory(ps + 0x15e, 1).tobytes(), 'little')
ag = int(gdb.parse_and_eval('&alloc_globals')) & 0xffffffffffffffff
h = u64(inf, ag)
mc = u64(inf, h + 0x140)
cc = u64(inf, h + 0x148)
rsize = u64(inf, h + 0x118)
print("PS id=%#x md=%#x send_cookie=%d hsv=%#x" % (pid, md, sc, u64(inf, ps + 0x168)), flush=True)
print("ID [%s]" % ("%#x chunk=%#x page=%#x" % (pid, pid & ~0x1fffff, (pid & 0x1fffff) >> 12) if pid else "NULL"), flush=True)
print("MD [%s]" % ("%#x chunk=%#x page=%#x" % (md, md & ~0x1fffff, (md & 0x1fffff) >> 12) if md else "NULL"), flush=True)
print("BASEDIR [%s]" % ("%#x chunk=%#x page=%#x" % (bd, bd & ~0x1fffff, (bd & 0x1fffff) >> 12) if bd else "NULL"), flush=True)
print("HEAP h=%#x main=%#x cached=%#x rsize=%#x" % (h, mc, cc, rsize), flush=True)
c = cc
i = 0
while c and i < 80 and c != mc:
    try:
        print("  cache[%02d] %#x fp=%d next=%#x" % (i, c, u32(inf, c + 0x18), u64(inf, c + 8)), flush=True)
    except Exception as e:
        print("  cache[%02d] %#x ERR %r" % (i, c, e), flush=True)
        break
    c = u64(inf, c + 8)
    i += 1
end
quit
