#!/usr/bin/env python3
"""Analyze frames from the new sandbox video to diagnose what's shown."""
import struct, zlib
from pathlib import Path

FRAMES_DIR = Path("/tmp/sb2")

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
        if ftype == 0: pass
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
    samples = []
    for gy in range(36):
        for gx in range(64):
            x = (gx * width) // 64
            y = (gy * height) // 36
            off = y * stride + x * bpp
            samples.append((out[off], out[off+1], out[off+2]))
    n = len(samples)
    avg = tuple(sum(c[i] for c in samples) // n for i in range(3))
    bins = {}
    for r, g, b in samples:
        bins[(r >> 5, g >> 5, b >> 5)] = bins.get((r >> 5, g >> 5, b >> 5), 0) + 1
    unique = len(bins)
    dominant = max(bins.items(), key=lambda x: x[1])
    # Detect specific regions
    # Top URL bar (y=0-28): teal(0f766e ~ (3,30,3-4)/8 ~ bin (3,30,3))... let's just check what's in y=0-28
    top_samples = [(out[(y*height//36)*stride + (x*width//64)*bpp:][:3]) for y in range(2) for x in range(64)]
    top_avg = tuple(sum(c[i] for c in top_samples)//len(top_samples) for i in range(3)) if top_samples else (0,0,0)
    # Banner area (y=28-90) — redirects banner
    mid_samples = [(out[(y*height//36)*stride + (x*width//64)*bpp:][:3]) for y in range(2,5) for x in range(64)]
    mid_avg = tuple(sum(c[i] for c in mid_samples)//len(mid_samples) for i in range(3)) if mid_samples else (0,0,0)
    # Bottom stats bar (y=680-720)
    bot_samples = [(out[(y*height//36)*stride + (x*width//64)*bpp:][:3]) for y in range(34,36) for x in range(64)]
    bot_avg = tuple(sum(c[i] for c in bot_samples)//len(bot_samples) for i in range(3)) if bot_samples else (0,0,0)
    # Main body (y=90-680)
    body_samples = [(out[(y*height//36)*stride + (x*width//64)*bpp:][:3]) for y in range(5,34) for x in range(64)]
    body_avg = tuple(sum(c[i] for c in body_samples)//len(body_samples) for i in range(3)) if body_samples else (0,0,0)
    body_bins = {}
    for r, g, b in body_samples:
        body_bins[(r >> 6, g >> 6, b >> 6)] = body_bins.get((r >> 6, g >> 6, b >> 6), 0) + 1
    body_unique = len(body_bins)
    return {
        "frame": path.stem,
        "avg": avg,
        "unique": unique,
        "dom_pct": round(dominant[1] / n * 100, 1),
        "top": top_avg,
        "mid": mid_avg,
        "body_avg": body_avg,
        "body_unique": body_unique,
        "bot": bot_avg,
    }

frames = sorted(FRAMES_DIR.glob("*.png"))
print(f"Found {len(frames)} frames\n")
print(f"{'frame':<10} {'avg_rgb':<22} {'top_rgb':<22} {'mid_rgb':<22} {'body_avg':<22} {'body_uniq':<10} {'bot_rgb'}")
for f in frames:
    info = analyze_png(f)
    print(f"{info['frame']:<10} {str(info['avg']):<22} {str(info['top']):<22} {str(info['mid']):<22} {str(info['body_avg']):<22} {info['body_unique']:<10} {str(info['bot'])}")
