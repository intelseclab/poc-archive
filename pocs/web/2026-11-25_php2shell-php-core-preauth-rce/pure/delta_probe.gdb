set pagination off
set confirm off
python
import gdb
def u64(inf,a): return int.from_bytes(inf.read_memory(a,8).tobytes(),'little')
inf=gdb.selected_inferior()
ps=int(gdb.parse_and_eval('&ps_globals')) & 0xffffffffffffffff
pid=u64(inf,ps+0x10)
md=u64(inf,ps+0x60)
ag=int(gdb.parse_and_eval('&alloc_globals')) & 0xffffffffffffffff
h=u64(inf,ag)
main=h & ~0x1fffff
z=int(gdb.parse_and_eval('(unsigned long)&zval_ptr_dtor'))
lib=z-0x65eb60
idc=(pid & ~0x1fffff) if pid else 0
print("PROBE lib=%#x z=%#x main=%#x id=%#x idchunk=%#x md=%#x" % (lib,z,main,pid,idc,md), flush=True)
if idc:
    print("DELTA lib-id=%#x main-id=%#x" % (lib-idc, main-idc), flush=True)
end
quit
