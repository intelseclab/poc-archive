set pagination off
set confirm off
python
import gdb
def u64(inf,a): return int.from_bytes(inf.read_memory(a,8).tobytes(),'little')
inf=gdb.selected_inferior()
ps=int(gdb.parse_and_eval('&ps_globals')) & 0xffffffffffffffff
pid=u64(inf,ps+0x10)
chunk=pid & ~0x1fffff
print("id=%#x chunk=%#x" % (pid,chunk), flush=True)
for off in (0x1ff000, 0x200000, 0x200040, 0x1fe000):
    try:
        v=u64(inf, chunk+off)
        print("  chunk+%#x = %#x" % (off, v), flush=True)
    except Exception as e:
        print("  chunk+%#x ERR %r" % (off,e), flush=True)
end
quit
