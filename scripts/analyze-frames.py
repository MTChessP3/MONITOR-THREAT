#!/usr/bin/env python3
"""Analyze frames extracted from the sandbox video webm to detect what's shown."""
import os, struct, zlib
from pathlib import Path

FRAMES_DIR = Path("/tmp/sandbox_frames")

def analyze_png(path):
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    pos = 8
    width = height = color_type = 0
    idat = []
    while pos < len(data):
        length = struct.unpack(">I", data[pos:pos+4])[0]
        ctype = data[pos+4:pos+8]
        body = data[pos+8:pos+8+length]
        if ctype == b"IHDR":
            width, height = struct.unpack(">II", body[:8])
            color_type = body[9]
        elif ctype == b"IDAT":
            idat.append(body)
        elif ctype == b"IEND":
            break
        pos += 12 + length
    raw = zlib.decompress(b"".join(idat))
    bpp = 3 if color_type == 2 else 4
    stride = width * bpp
    prev = bytearray(stride)
    out = bytearray(stride * height)
    pos = 0
    for y in range(height):
        ftype = raw[pos]
        line = bytearray(raw[pos+1:pos+1+stride])
        pos += 1 + stride
        if ftype == 0:
            pass
        elif ftype == 1:
            for i in range(bpp, stride): line[i] = (line[i] + line[i-bpp]) & 0xff
        elif ftype == 2:
            for i in range(stride): line[i] = (line[i] + prev[i]) & 0xff
        elif ftype == 3:
            for i in range(stride):
                a = line[i-bpp] if i >= bpp else 0
                line[i] = (line[i] + (a + prev[i]) // 2) & 0xff
        elif ftype == 4:
            for i in range(stride):
                a = line[i-bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i-bpp] if i >= bpp else 0
                p = a + b - c
                pa, pb, pc = abs(p-a), abs(p-b), abs(p-c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 0xff
        out[y*stride:(y+1)*stride] = line
        prev = line
    # Sample 32x18 grid (matches 16:9 aspect)
    samples = []
    for gy in range(18):
        for gx in range(32):
            x = (gx * width) // 32
            y = (gy * height) // 18
            off = y * stride + x * bpp
            samples.append((out[off], out[off+1], out[off+2]))
    n = len(samples)
    avg = tuple(sum(c[i] for c in samples) // n for i in range(3))
    bins = {}
    for r, g, b in samples:
        bins[(r >> 5, g >> 5, b >> 5)] = bins.get((r >> 5, g >> 5, b >> 5), 0) + 1
    unique = len(bins)
    dominant = max(bins.items(), key=lambda x: x[1])
    is_dark = sum(avg) < 200
    is_white = sum(avg) > 720
    dark_ink = sum(1 for r, g, b in samples if (r + g + b) < 200)
    # Detect "MONITOR-THREAT" red: ~ (233, 69, 96) → bin (7, 2, 3)
    monitor_red = bins.get((7, 2, 3), 0)
    return {
        "frame": path.stem,
        "avg": avg,
        "unique": unique,
        "dominant_pct": round(dominant[1] / n * 100, 1),
        "is_dark": is_dark,
        "is_white": is_white,
        "ink_pct": round(dark_ink / n * 100, 1),
        "monitor_red_pct": round(monitor_red / n * 100, 1),
    }

frames = sorted(FRAMES_DIR.glob("*.png"))
print(f"Found {len(frames)} frames\n")
print(f"{'frame':<14} {'avg_rgb':<22} {'uniq':<5} {'dom%':<6} {'ink%':<6} {'mt_red%':<8} {'bg'}")
for f in frames:
    info = analyze_png(f)
    bg = "DARK" if info["is_dark"] else ("WHITE" if info["is_white"] else "color")
    print(f"{info['frame']:<14} {str(info['avg']):<22} {info['unique']:<5} {info['dominant_pct']:<6} {info['ink_pct']:<6} {info['monitor_red_pct']:<8} {bg}")
