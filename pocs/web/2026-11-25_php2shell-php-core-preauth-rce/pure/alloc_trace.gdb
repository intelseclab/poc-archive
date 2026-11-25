set pagination off
set confirm off
python
import gdb

def u64(inf,a): return int.from_bytes(inf.read_memory(a,8).tobytes(),'little')

state = {"n": 0}

class AB(gdb.Breakpoint):
    def __init__(self):
        super().__init__("zend_mm_alloc_large", internal=True)
    def stop(self):
        state["n"] += 1
        idx = state["n"]
        try:
            size = int(gdb.parse_and_eval('$rdi')) & 0xffffffffffffffff
        except Exception:
            size = 0
        try:
            heap = int(gdb.parse_and_eval('*(unsigned long*)&alloc_globals')) & 0xffffffffffffffff
        except Exception:
            heap = 0
        class Fin(gdb.FinishBreakpoint):
            def stop(self):
                try:
                    rv = int(self.return_value) & 0xffffffffffffffff
                    chunk = rv & ~0x1fffff
                    print("ALLOC %d size=%#x ret=%#x chunk=%#x page=%#x" % (
                        idx, size, rv, chunk, (rv & 0x1fffff) >> 12), flush=True)
                except Exception as e:
                    print("ALLOC %d size=%#x retERR %r" % (idx, size, e), flush=True)
                return False
        Fin(internal=True)
        return False
AB()

class IDB(gdb.Breakpoint):
    def __init__(self):
        super().__init__("php_session_rfc1867_callback", internal=True)
    def stop(self):
        try:
            ev = int(gdb.parse_and_eval('$rdi')) & 0xffffffffffffffff
            if ev == 5:
                inf = gdb.selected_inferior()
                ps = int(gdb.parse_and_eval('&ps_globals')) & 0xffffffffffffffff
                pid = u64(inf, ps + 0x10)
                print("IDCHUNK id=%#x chunk=%#x page=%#x" % (
                    pid, pid & ~0x1fffff, (pid & 0x1fffff) >> 12), flush=True)
        except Exception as e:
            print("IDERR", repr(e), flush=True)
        return False
IDB()
end
continue
