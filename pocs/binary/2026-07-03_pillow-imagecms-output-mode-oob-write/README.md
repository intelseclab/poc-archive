# Pillow ImageCms Mutable output_mode Heap OOB Write

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-03 |
| **Last Updated** | 2026-07 |
| **Author / Researcher** | bikini (@ashdfrkl) — original discovery; mirrored via exploitarium |
| **CVE / Advisory** | None assigned as of 2026-07-03 |
| **Category** | binary |
| **Severity** | High |
| **CVSS Score** | Not yet scored (no CVE/CVSS assigned) |
| **Status** | PoC |
| **Tags** | pillow, imagecms, littlecms, heap-overflow, oob-write, python, image-processing, memory-corruption |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Pillow (Python Imaging Library fork), `PIL.ImageCms` module |
| **Versions Affected** | 12.3.0 (verified); build with LittleCMS2 support enabled |
| **Language / Platform** | Python (calls into C extension `_imagingcms`) |
| **Authentication Required** | No |
| **Network Access Required** | No |

---

## Summary

Pillow's `ImageCms.buildTransform()` creates a reusable LittleCMS-backed transform object and stores mutable `input_mode`/`output_mode` attributes on the Python wrapper. `ImageCmsTransform.apply()` trusts these mutable attributes both to validate image modes and to allocate the destination buffer, while the underlying C transform still operates using the original LittleCMS format it was built with. By mutating `transform.output_mode` from `RGBA` to `L` after the transform is built (e.g. from `RGB`→`RGBA`) and then calling the normal high-level `ImageCms.applyTransform()` API, the destination image is allocated far smaller (1 byte per pixel) than what the native auxiliary-channel copy routine writes (4 bytes per pixel), producing a heap out-of-bounds write inside `_imagingcms.c`. This PoC was published by a pseudonymous independent researcher (bikini/ashdfrkl) as part of the uncoordinated "exploitarium" vulnerability dump; it has not been vendor-confirmed.

---

## Vulnerability Details

### Root Cause

`ImageCms.py` keeps mutable `input_mode`/`output_mode` attributes on the Python transform wrapper and uses them both for mode validation and destination buffer allocation, while the C extension (`_imagingcms.c`) derives its copy stride/offsets from the immutable LittleCMS transform format created at build time. The two states can diverge, and the native code never re-validates the destination buffer size against the actual transform output format.

### Attack Vector

1. Build an ImageCms transform from `RGB` to `RGBA` via `ImageCms.buildTransform()`.
2. Create a 64x64 `RGB` source image.
3. Mutate the transform wrapper's `output_mode` attribute from `RGBA` to `L` (smaller pixel size).
4. Call the standard high-level `ImageCms.applyTransform(source, transform)` API.
5. Pillow allocates the destination image sized for `L` (1 byte/pixel) while the native `pyCMScopyAux()` copies auxiliary channel bytes using the original 4-byte/pixel `RGBA` layout, writing past the allocated heap buffer.

### Impact

Heap out-of-bounds write reachable from ordinary Python API calls against a stock Pillow build with LittleCMS2 enabled. Depending on heap layout, this manifests as a crash (heap metadata corruption / process abort) and is a plausible primitive for further memory-corruption exploitation in processes that use Pillow to handle untrusted images with color management transforms.

---

## Environment / Lab Setup

```
Target:   Pillow 12.3.0 built with LittleCMS2 (_imagingcms) support
Attacker: Python 3.10+, stock Pillow 12.3.0 install (optionally built under AddressSanitizer for confirmation)
```

---

## Proof of Concept

### PoC Script

> See `poc.py` in this folder.

```bash
python poc.py
```

The script builds an sRGB `RGB`→`RGBA` ImageCms transform, creates a 64x64 RGB source image, mutates `transform.output_mode` to `L`, and calls `ImageCms.applyTransform()`. On a stock build this aborts with a heap allocator error; under AddressSanitizer it reports a heap-buffer-overflow write of size 1 in `pyCMScopyAux` inside `_imagingcms.c`.

---

## Detection & Indicators of Compromise

```
# Fatal Python error: Aborted, or glibc "malloc(): invalid size (unsorted)"
# raised from PIL/ImageCms.py during ImageCms.applyTransform()/tobytes()

# AddressSanitizer builds report:
# ERROR: AddressSanitizer: heap-buffer-overflow ... in pyCMScopyAux _imagingcms.c
```

**Signs of compromise:**
- Unexpected process crashes or aborts in applications that process untrusted images through `PIL.ImageCms` transforms
- Heap corruption / allocator abort signatures traced back to `_imagingcms.c` (`pyCMScopyAux`, `pyCMSdoTransform`)
- Anomalous `output_mode` mutation on `ImageCmsTransform` objects in application code paths that accept attacker-influenced parameters

---

## Remediation

| Action | Detail |
|---|---|
| **Primary fix** | No vendor patch confirmed as of 2026-07-03 — monitor for advisory |
| **Interim mitigation** | Do not mutate `input_mode`/`output_mode` on `ImageCmsTransform` objects after construction; validate destination buffer size against the transform's actual LittleCMS output format before calling `apply()`/`applyTransform()`; run untrusted-image processing pipelines in a sandboxed/isolated process |

---

## References

- [Source repository (bikini/exploitarium)](https://github.com/bikini/exploitarium/tree/main/pillow-imagecms-output-mode-oob-poc)

---

## Notes

Mirrored from https://github.com/bikini/exploitarium (folder: `pillow-imagecms-output-mode-oob-poc`) on 2026-07-03. No CVE has been assigned as of ingestion — this is an uncoordinated disclosure by a pseudonymous researcher; treat with appropriate caution pending vendor confirmation.
