# FFmpeg RASC Decoder DLTA Heap Out-of-Bounds Write

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-03 |
| **Last Updated** | 2026-06 |
| **Author / Researcher** | bikini (@ashdfrkl) — original discovery; mirrored via exploitarium |
| **CVE / Advisory** | None assigned as of 2026-07-03 |
| **Category** | binary |
| **Severity** | Critical |
| **CVSS Score** | Not yet scored (no CVE/CVSS assigned) |
| **Status** | PoC |
| **Tags** | ffmpeg, libavcodec, heap-overflow, rasc, oob-write, media-parsing, codec, memory-corruption |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | FFmpeg, `libavcodec` RASC decoder (`AV_CODEC_ID_RASC`) |
| **Versions Affected** | Upstream master `bcd2c69e087a09b07cf45c6bd2428ee1ccb2925c` (2026-06-26) |
| **Language / Platform** | C, targets `libavcodec`; reachable via AVI/RIFF files with a `RASC` FourCC |
| **Authentication Required** | No |
| **Network Access Required** | No (local/media-file processing; delivery via crafted media file is out of scope) |

---

## Summary

FFmpeg's RASC decoder (`decode_dlta()` in `libavcodec/rasc.c`) tracks a row cursor and only checks whether it has reached the end of the current row *after* certain operations, rather than before. Several DLTA run types (`4`, `7`, `12`, `13`) perform 32-bit reads/writes at the cursor position before this boundary check runs, so a crafted delta chunk positioned at the last byte of a row (e.g., `x=63` on a 64-pixel-wide PAL8 row) causes a 4-byte read/write that crosses the row's heap allocation boundary by 3 bytes. The included PoC demonstrates this is exploitable beyond a crash: it places a callback function pointer immediately after the 64-byte PAL8 plane via a custom `get_buffer2` allocator, then uses DLTA run type 7 (whose 32-bit `fill` value comes directly from the bitstream) to overwrite the low 3 bytes of that adjacent pointer, redirecting it from a benign callback to an attacker-chosen one that is invoked after decode completes. The researcher confirmed the underlying heap-buffer-overflow with AddressSanitizer against current FFmpeg master and demonstrated full callback hijack (launching a calculator) in a non-ASAN build. This PoC was published by a pseudonymous independent researcher (bikini/ashdfrkl) as part of the uncoordinated "exploitarium" vulnerability dump; it has not been vendor-confirmed.

---

## Vulnerability Details

### Root Cause

`decode_dlta()`'s `NEXT_LINE` macro only checks `cx >= w * s->bpp` (row-end) after each operation completes, not before. DLTA run type `7` performs `AV_WL32(b1 + cx, ...)` / `AV_WL32(b2 + cx, fill)` — a 4-byte read and write — at the current cursor position before advancing and checking row bounds, so a cursor positioned at the last valid byte of a row causes the 32-bit access to read/write 3 bytes past the row's heap allocation.

### Attack Vector

1. Attacker crafts a RASC bitstream with an `INIT` chunk declaring a small frame (e.g., width=64, height=1, PAL8 format) so the decoder allocates a tightly-sized 64-byte row plane.
2. Attacker crafts a `DLTA` chunk using run type `7` positioned at `x=63, w=1, h=1` — the last byte of the row — with an embedded 32-bit `fill` value.
3. A vulnerable FFmpeg build decodes the crafted packet through the public `libavcodec` API (`avcodec_open2`/`avcodec_send_packet`/`avcodec_receive_frame`); `decode_dlta()` performs the out-of-bounds 32-bit write at the row boundary before its bounds check triggers.
4. If attacker-controllable data (e.g., a function pointer, as in the PoC's custom `get_buffer2` frame layout) is allocated immediately adjacent to the frame plane, the crafted `fill` value overwrites the low bytes of that adjacent value.
5. If the overwritten value is later used (e.g., a callback pointer invoked by the host application), execution can be redirected to attacker-influenced code, as demonstrated by the PoC's calculator-launch proof.

### Impact

Heap out-of-bounds write in `libavcodec`'s RASC decoder, reachable via crafted AVI/RIFF media containing a `RASC`-tagged stream; depending on adjacent heap layout and the host application's memory usage, this can escalate from memory corruption to control-flow hijack, as demonstrated by the included callback-redirection PoC.

---

## Environment / Lab Setup

```
Target:   FFmpeg built from source at bcd2c69e087a09b07cf45c6bd2428ee1ccb2925c (or later, unpatched) with RASC decoder enabled
Attacker: Linux or WSL, gcc, make, zlib development headers, FFmpeg build dependencies
```

---

## Proof of Concept

### PoC Script

> See `ffmpeg_rasc_dlta_calc_poc.c`, `ffmpeg_rasc_dlta_calc_poc_portable.c`, `rasc_dlta_os_helper.py`, `build_from_checkout.sh`, and `run_calc_pop.sh` in this folder.

```bash
git clone https://github.com/FFmpeg/FFmpeg.git /tmp/ffmpeg
./build_from_checkout.sh /tmp/ffmpeg /tmp/ffmpeg-rasc-build ./ffmpeg_rasc_dlta_calc_poc
./run_calc_pop.sh ./ffmpeg_rasc_dlta_calc_poc
```

`build_from_checkout.sh` configures and builds a RASC-only static `libavcodec` (`--disable-everything --enable-decoder=rasc`) and links the PoC against it. The PoC builds a crafted RASC packet in memory, decodes it via the public libavcodec API with a custom `get_buffer2` callback that places a benign function pointer directly after the 64-byte PAL8 plane, and verifies the DLTA out-of-bounds write overwrites that pointer to redirect it to an attacker-chosen callback, which it then invokes to prove control-flow hijack (writing a marker file and launching a calculator).

---

## Detection & Indicators of Compromise

```
# AddressSanitizer heap-buffer-overflow reports in libavcodec/rasc.c decode_dlta()
# FFmpeg/libavcodec crashes or anomalous process behavior when processing AVI/RIFF
# files containing a RASC-tagged video stream
```

**Signs of compromise:**
- Crashes, hangs, or anomalous behavior in applications embedding `libavcodec` shortly after processing untrusted AVI/RIFF media
- ASAN/crash-reporting output referencing `decode_dlta` or `rasc.c` in the stack trace
- Unexpected child process spawns from media-processing services correlated with ingestion of attacker-supplied video files

---

## Remediation

| Action | Detail |
|---|---|
| **Primary fix** | No vendor patch confirmed as of 2026-07-03 — monitor FFmpeg for a fix; the source suggests guarding every 32-bit DLTA access with `cx + 4 <= w * s->bpp` before performing the read/write, applied to run types `4`, `7`, `12`, and `13` |
| **Interim mitigation** | Disable the RASC decoder (`--disable-decoder=rasc`) in builds that process untrusted media, or run media decoding in a sandboxed/isolated process with no sensitive adjacent memory |

---

## References

- [Source repository (bikini/exploitarium)](https://github.com/bikini/exploitarium/tree/main/ffmpeg-rasc-dlta-calc-poc)

---

## Notes

Mirrored from https://github.com/bikini/exploitarium (folder: `ffmpeg-rasc-dlta-calc-poc`) on 2026-07-03. No CVE has been assigned as of ingestion — this is an uncoordinated disclosure by a pseudonymous researcher; treat with appropriate caution pending vendor confirmation.
