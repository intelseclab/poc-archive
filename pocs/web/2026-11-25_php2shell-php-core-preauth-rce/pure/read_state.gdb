set pagination off
set confirm off
python
import gdb
def u64(inf,a): return int.from_bytes(inf.read_memory(a,8).tobytes(),'little')
inf=gdb.selected_inferior()
ps=int(gdb.parse_and_eval('&ps_globals')) & 0xffffffffffffffff
ag=int(gdb.parse_and_eval('&alloc_globals')) & 0xffffffffffffffff
h=u64(inf,ag); main=h & ~0x1fffff
pid=u64(inf,ps+0x10); md=u64(inf,ps+0x60); hsv=u64(inf,ps+0x168)
sc=int.from_bytes(inf.read_memory(ps+0x15e,1).tobytes(),'little')
z=int(gdb.parse_and_eval('(unsigned long)&zval_ptr_dtor'))
print("STATE main=%#x mainoff_hsv=%s lib=%#x id=%#x idoff=%s md=%#x hsv=%#x send_cookie=%d" % (
    main, ("%#x" % (hsv-main)) if hsv else "NULL", z-0x65eb60, pid,
    ("%#x" % (pid-main)) if pid else "NULL", md, hsv, sc), flush=True)
end
quit
