set pagination off
set confirm off
python
import gdb
def u64(inf,a): return int.from_bytes(inf.read_memory(a,8).tobytes(),'little')
inf=gdb.selected_inferior()
ps=int(gdb.parse_and_eval('&ps_globals')) & 0xffffffffffffffff
pid=u64(inf,ps+0x10)
if not pid:
    print("NO_ID")
else:
    chunk=pid & ~0x1fffff
    print("id=%#x idchunk=%#x idoff=%#x" % (pid,chunk,pid&0x1fffff), flush=True)
    for off in (0x1fe000,0x1ff000,0x200000,0x200040,0x200010,0x1ff800):
        try:
            print("  +%#x = %#x" % (off, u64(inf,chunk+off)), flush=True)
        except Exception as e:
            print("  +%#x ERR" % off, flush=True)
end
quit
