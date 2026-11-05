#!/usr/bin/env python3
"""Generate DARKBYTE ARES's original, license-clean visual assets.

Every asset in frontend/public/assets is rendered procedurally from primitives —
no third-party photography, stock imagery, or generated text artifacts. The
script is deterministic (fixed seed per asset) so releases are reproducible.

Usage: python scripts/generate_assets.py
"""
from __future__ import annotations

import math
import random
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "frontend" / "public" / "assets"
OUT.mkdir(parents=True, exist_ok=True)

BG = (8, 11, 18)
CYAN = (0, 229, 255)
GREEN = (0, 255, 136)
VIOLET = (139, 92, 246)
AMBER = (245, 158, 11)
RED = (255, 76, 106)
TEXT = (229, 231, 235)
MUTED = (100, 116, 139)
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_REGULAR = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def font(path: str, size: int):
    try:
        return ImageFont.truetype(path, size)
    except OSError:
        return ImageFont.load_default()


def gradient_canvas(w: int, h: int, seed: int, accent=CYAN, secondary=VIOLET) -> Image.Image:
    rng = np.random.default_rng(seed)
    y = np.linspace(0, 1, h)[:, None]
    x = np.linspace(0, 1, w)[None, :]
    arr = np.zeros((h, w, 3), dtype=np.float32)
    arr[..., 0] = 5 + 7 * y
    arr[..., 1] = 8 + 9 * y
    arr[..., 2] = 15 + 14 * y
    # Broad accent fields.
    for cx, cy, radius, color, strength in [
        (0.18, 0.22, 0.55, accent, 0.15),
        (0.78, 0.18, 0.50, secondary, 0.13),
        (0.65, 0.88, 0.55, GREEN, 0.07),
        (0.95, 0.60, 0.30, accent, 0.09),
    ]:
        d = np.sqrt((x - cx) ** 2 + ((y - cy) * (h / w)) ** 2)
        glow = np.exp(-(d / radius) ** 2 * 3.0) * strength
        for i in range(3):
            arr[..., i] += color[i] * glow
    arr += rng.normal(0, 2.0, arr.shape)
    return Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8), "RGB").convert("RGBA")


def add_noise(img: Image.Image, amount=10):
    arr = np.array(img).astype(np.int16)
    rng = np.random.default_rng(42)
    noise = rng.normal(0, amount, (img.height, img.width, 1))
    arr[..., :3] = np.clip(arr[..., :3] + noise, 0, 255)
    return Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8), "RGBA")


def vignette(img: Image.Image, strength=0.72) -> Image.Image:
    w, h = img.size
    y, x = np.mgrid[0:h, 0:w]
    cx, cy = w / 2, h / 2
    d = np.sqrt(((x - cx) / (w * 0.62)) ** 2 + ((y - cy) / (h * 0.62)) ** 2)
    mask = np.clip((d - 0.45) * strength, 0, 0.82)
    arr = np.array(img).astype(np.float32)
    arr[..., :3] *= (1 - mask[..., None])
    return Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8), "RGBA")


def glow(layer: Image.Image, radius=12, gain=1.0) -> Image.Image:
    out = layer.filter(ImageFilter.GaussianBlur(radius))
    if gain != 1.0:
        arr = np.array(out).astype(np.float32)
        arr[..., 3] = np.clip(arr[..., 3] * gain, 0, 255)
        out = Image.fromarray(arr.astype(np.uint8), "RGBA")
    return out


def compose(base: Image.Image, layer: Image.Image, blur=10, gain=1.0):
    g = glow(layer, blur, gain)
    base.alpha_composite(g)
    base.alpha_composite(layer)
    return base


def draw_gradient_line(draw, p1, p2, c1, c2, width, steps=32):
    for i in range(steps):
        t0, t1 = i / steps, (i + 1) / steps
        a = (p1[0] + (p2[0] - p1[0]) * t0, p1[1] + (p2[1] - p1[1]) * t0)
        b = (p1[0] + (p2[0] - p1[0]) * t1, p1[1] + (p2[1] - p1[1]) * t1)
        draw.line([a, b], fill=(*lerp(c1, c2, t0), 255), width=width)


def hexagon(cx, cy, r, rot=math.pi / 6):
    return [(cx + r * math.cos(rot + i * math.pi / 3), cy + r * math.sin(rot + i * math.pi / 3)) for i in range(6)]


def perspective_grid(base, scale=1, horizon=0.58, color=CYAN, alpha=56):
    w, h = base.size
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    hy = int(h * horizon)
    vx, vy = w * 0.52, hy
    for i in range(-18, 19):
        x_end = vx + i * w * 0.085
        d.line([(vx, vy), (x_end, h)], fill=(*color, alpha), width=max(1, int(scale)))
    # Horizontal bands with perspective compression.
    y = hy
    step = 4
    while y < h:
        t = (y - hy) / max(1, h - hy)
        a = int(alpha * (0.25 + t * 0.8))
        d.line([(0, y), (w, y)], fill=(*color, a), width=max(1, int(scale)))
        step *= 1.23
        y += step
    return compose(base, layer, blur=1, gain=1.1)


def fine_grid(base, color=(80, 100, 140), alpha=18, spacing=48):
    w, h = base.size
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for x in range(0, w, spacing):
        d.line([(x, 0), (x, h)], fill=(*color, alpha), width=1)
    for y in range(0, h, spacing):
        d.line([(0, y), (w, y)], fill=(*color, alpha), width=1)
    base.alpha_composite(layer)
    return base


def particle_field(base, seed, count=90, color=CYAN):
    rng = random.Random(seed)
    w, h = base.size
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for _ in range(count):
        x, y = rng.randrange(w), rng.randrange(h)
        r = rng.choice([0.5, 0.8, 1, 1.4, 2])
        a = rng.randint(30, 150)
        d.ellipse([x - r, y - r, x + r, y + r], fill=(*color, a))
    return compose(base, layer, blur=2, gain=0.8)


def corner_hud(base, color=CYAN):
    w, h = base.size
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    pad, ln = int(w * 0.035), int(w * 0.055)
    for (x, y, sx, sy) in [(pad, pad, 1, 1), (w - pad, pad, -1, 1), (pad, h - pad, 1, -1), (w - pad, h - pad, -1, -1)]:
        d.line([(x, y), (x + sx * ln, y)], fill=(*color, 165), width=2)
        d.line([(x, y), (x, y + sy * ln)], fill=(*color, 165), width=2)
        d.ellipse([x - 2, y - 2, x + 2, y + 2], fill=(*GREEN, 210))
    return compose(base, layer, blur=4, gain=0.8)


def wire_globe(base, cx, cy, radius, seed=3, color=CYAN):
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    rng = random.Random(seed)
    # Latitude / longitude wireframe.
    for i in range(1, 9):
        ry = radius * math.sin((i / 9) * math.pi - math.pi / 2)
        rx = radius * math.cos((i / 9) * math.pi - math.pi / 2)
        d.ellipse([cx - radius, cy - abs(ry), cx + radius, cy + abs(ry)], outline=(*color, 38), width=2)
    for i in range(1, 12):
        rx = radius * math.sin((i / 12) * math.pi)
        d.ellipse([cx - rx, cy - radius, cx + rx, cy + radius], outline=(*color, 26), width=1)
    d.ellipse([cx - radius, cy - radius, cx + radius, cy + radius], outline=(*color, 150), width=2)
    # Sparse continents / nodes.
    for _ in range(48):
        theta = rng.uniform(0, 2 * math.pi)
        phi = math.acos(rng.uniform(-1, 1))
        x = cx + radius * math.sin(phi) * math.cos(theta)
        y = cy + radius * math.cos(phi) * 0.92
        if math.sqrt((x - cx) ** 2 + (y - cy) ** 2) < radius * 0.94:
            d.ellipse([x - 2, y - 2, x + 2, y + 2], fill=(*GREEN, rng.randint(80, 200)))
    return compose(base, layer, blur=7, gain=1.15)


def hud_rings(base, cx, cy, radius, color=CYAN, seed=1):
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for i, (r, a, wd, start, end) in enumerate([
        (radius * 1.36, 42, 1, 210, 510),
        (radius * 1.23, 68, 2, 280, 440),
        (radius * 1.08, 110, 1, 0, 360),
        (radius * 0.72, 60, 1, 30, 250),
    ]):
        d.arc([cx - r, cy - r, cx + r, cy + r], start=start, end=end, fill=(*color, a), width=wd)
    rng = random.Random(seed)
    for _ in range(24):
        ang = rng.uniform(0, math.pi * 2)
        r0 = radius * rng.uniform(1.0, 1.38)
        r1 = r0 + rng.uniform(3, 20)
        x0, y0 = cx + r0 * math.cos(ang), cy + r0 * math.sin(ang)
        x1, y1 = cx + r1 * math.cos(ang), cy + r1 * math.sin(ang)
        d.line([(x0, y0), (x1, y1)], fill=(*color, rng.randint(35, 130)), width=1)
    return compose(base, layer, blur=5, gain=1.1)


def network_graph(base, seed, count=26, spread=0.34, color=CYAN):
    rng = random.Random(seed)
    w, h = base.size
    nodes = []
    for _ in range(count):
        nodes.append((rng.uniform(w * (0.5 - spread), w * (0.5 + spread)), rng.uniform(h * 0.2, h * 0.82), rng.choice([2, 2, 3, 4])))
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for i, a in enumerate(nodes):
        for j, b in enumerate(nodes[i + 1:], start=i + 1):
            dist = math.dist(a[:2], b[:2])
            if dist < w * 0.19 and rng.random() < 0.5:
                col = GREEN if (i + j) % 5 == 0 else color
                d.line([a[:2], b[:2]], fill=(*col, rng.randint(18, 76)), width=1)
    for x, y, r in nodes:
        d.ellipse([x - r * 2.5, y - r * 2.5, x + r * 2.5, y + r * 2.5], outline=(*color, 55), width=1)
        d.ellipse([x - r, y - r, x + r, y + r], fill=(*color, 215))
    return compose(base, layer, blur=7, gain=1.25)


def data_bars(base, x, y, width, height, seed=5, color=CYAN):
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    rng = random.Random(seed)
    n = 30
    bw = width / n
    for i in range(n):
        bh = rng.uniform(0.1, 1) * height
        c = GREEN if i % 7 == 0 else color
        d.rectangle([x + i * bw, y + height - bh, x + i * bw + bw * 0.42, y + height], fill=(*c, rng.randint(40, 125)))
    return compose(base, layer, blur=6, gain=1.1)


def save_webp(img, name, quality=86):
    img = img.convert("RGB")
    img.save(OUT / name, "WEBP", quality=quality, method=6)
    print(f"  ✓ {name}  {img.width}×{img.height}")


def save_png(img, name):
    img.save(OUT / name, "PNG", optimize=True)
    print(f"  ✓ {name}  {img.width}×{img.height}")


# ─────────────────────────────────────────────────────────────────────────────
# Emblem + brand file
# ─────────────────────────────────────────────────────────────────────────────
def draw_emblem(draw: ImageDraw.ImageDraw, cx: float, cy: float, size: float):
    """Angular Ares mark: shield hex, orbital arcs, arrowhead core."""
    r = size / 2
    outer = hexagon(cx, cy, r * 0.94, math.pi / 6)
    inner = hexagon(cx, cy, r * 0.72, math.pi / 6)
    # Gradient outer hex.
    for i in range(len(outer)):
        draw_gradient_line(draw, outer[i], outer[(i + 1) % len(outer)], CYAN, GREEN, max(2, int(size * 0.009)), 20)
    # Cut corners / technical ticks.
    for i in range(6):
        p = outer[i]
        q = inner[i]
        draw.line([p, (p[0] + (q[0] - p[0]) * 0.36, p[1] + (q[1] - p[1]) * 0.36)], fill=(*CYAN, 110), width=max(1, int(size * 0.004)))
    # Inner chevron A.
    top = (cx, cy - r * 0.50)
    left = (cx - r * 0.48, cy + r * 0.38)
    right = (cx + r * 0.48, cy + r * 0.38)
    mid = (cx, cy + r * 0.08)
    draw_gradient_line(draw, top, left, CYAN, GREEN, max(3, int(size * 0.022)), 24)
    draw_gradient_line(draw, top, right, CYAN, GREEN, max(3, int(size * 0.022)), 24)
    draw_gradient_line(draw, left, (cx, cy + r * 0.22), GREEN, CYAN, max(2, int(size * 0.012)), 12)
    draw_gradient_line(draw, right, (cx, cy + r * 0.22), GREEN, CYAN, max(2, int(size * 0.012)), 12)
    draw.line([mid, (cx, cy + r * 0.47)], fill=(*GREEN, 220), width=max(2, int(size * 0.013)))
    # Orbit accent.
    draw.arc([cx - r * 1.08, cy - r * 0.45, cx + r * 1.08, cy + r * 0.45], 342, 198, fill=(*VIOLET, 150), width=max(1, int(size * 0.006)))
    draw.ellipse([cx + r * 0.92 - r * 0.035, cy - r * 0.16 - r * 0.035, cx + r * 0.92 + r * 0.035, cy - r * 0.16 + r * 0.035], fill=(*GREEN, 255))
    draw.ellipse([cx - r * 1.08 - r * 0.02, cy + r * 0.20 - r * 0.02, cx - r * 1.08 + r * 0.02, cy + r * 0.20 + r * 0.02], fill=(*CYAN, 210))


def spaced_text(draw, xy, text, fnt, fill, tracking=0, anchor_center=False):
    widths = [draw.textlength(ch, font=fnt) for ch in text]
    total = sum(widths) + tracking * (len(text) - 1)
    x, y = xy
    if anchor_center:
        x -= total / 2
    for ch, wd in zip(text, widths):
        draw.text((x, y), ch, font=fnt, fill=fill)
        x += wd + tracking
    return total


def make_logo():
    scale = 2
    w, h = 1600 * scale, 520 * scale
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    emblem = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    draw_emblem(ImageDraw.Draw(emblem), 250 * scale, 258 * scale, 330 * scale)
    img.alpha_composite(emblem.filter(ImageFilter.GaussianBlur(22 * scale)))
    img.alpha_composite(emblem)
    # Wordmark — crisp, no dark halo behind type.
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    f_brand = font(FONT_MONO, 38 * scale)
    f_title = font(FONT_BOLD, 196 * scale)
    f_sub = font(FONT_MONO, 27 * scale)
    spaced_text(d, (480 * scale, 108 * scale), "DARKBYTE", f_brand, (*GREEN, 235), 13 * scale)
    spaced_text(d, (474 * scale, 140 * scale), "ARES", f_title, (*TEXT, 255), 2 * scale)
    # Divider + subtitle.
    d.line([(484 * scale, 382 * scale), (1118 * scale, 382 * scale)], fill=(*CYAN, 120), width=2 * scale)
    d.rectangle([(484 * scale, 380 * scale), (564 * scale, 384 * scale)], fill=(*GREEN, 255))
    spaced_text(d, (484 * scale, 408 * scale), "OFFENSIVE SECURITY OPERATIONS", f_sub, (*MUTED, 255), 4 * scale)
    img.alpha_composite(layer)
    img = img.resize((1600, 520), Image.LANCZOS)
    save_png(img, "ares-logo.png")


def make_icon():
    scale = 4
    size = 512 * scale
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=112 * scale, fill=(*BG, 255))
    # Subtle inner panel.
    d.rounded_rectangle([14 * scale, 14 * scale, size - 14 * scale, size - 14 * scale], radius=100 * scale, outline=(*CYAN, 34), width=2 * scale)
    layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    dl = ImageDraw.Draw(layer)
    draw_emblem(dl, size / 2, size / 2, 340 * scale)
    img.alpha_composite(layer.filter(ImageFilter.GaussianBlur(18 * scale)))
    img.alpha_composite(layer)
    img = img.resize((512, 512), Image.LANCZOS)
    save_png(img, "ares-icon.png")


# ─────────────────────────────────────────────────────────────────────────────
# Scene assets
# ─────────────────────────────────────────────────────────────────────────────
def make_hero():
    w, h = 1920, 1080
    img = gradient_canvas(w, h, 7, CYAN, VIOLET)
    img = perspective_grid(img, 1, 0.64, CYAN, 48)
    img = fine_grid(img, (90, 110, 150), 14, 64)
    img = hud_rings(img, w * 0.76, h * 0.43, h * 0.34, CYAN, 8)
    img = wire_globe(img, w * 0.76, h * 0.43, h * 0.27, 14, CYAN)
    img = network_graph(img, 12, 34, 0.28, CYAN)
    img = particle_field(img, 4, 130)
    img = data_bars(img, w * 0.06, h * 0.34, w * 0.24, h * 0.27, 6, CYAN)
    # Data spine.
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for x in [w * 0.035, w * 0.965]:
        d.line([(x, h * 0.13), (x, h * 0.87)], fill=(*CYAN, 70), width=1)
        for y in [0.18, 0.31, 0.53, 0.74, 0.86]:
            d.rectangle([x - 3, h * y - 3, x + 3, h * y + 3], fill=(*GREEN, 180))
    # Light streaks.
    for i in range(9):
        y = h * (0.2 + i * 0.07)
        d.line([(w * 0.03, y), (w * (0.18 + i * 0.02), y + 30)], fill=(*CYAN, 25), width=1)
    img = compose(img, layer, blur=7, gain=1.1)
    img = corner_hud(img, CYAN)
    img = vignette(img, 0.8)
    img = add_noise(img, 4)
    save_webp(img, "cyber-hero.webp", 88)
    small = img.resize((960, 540), Image.LANCZOS)
    save_webp(small, "cyber-hero-960.webp", 84)


def make_network():
    w, h = 1600, 1000
    img = gradient_canvas(w, h, 21, CYAN, GREEN)
    img = perspective_grid(img, 1, 0.66, GREEN, 24)
    img = wire_globe(img, w * 0.52, h * 0.48, h * 0.33, 9, CYAN)
    img = hud_rings(img, w * 0.52, h * 0.48, h * 0.39, CYAN, 4)
    # Isometric subnet clusters.
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    rng = random.Random(33)
    clusters = [(w * 0.2, h * 0.34), (w * 0.78, h * 0.29), (w * 0.82, h * 0.68), (w * 0.24, h * 0.72), (w * 0.52, h * 0.48)]
    for cx, cy in clusters:
        pts = hexagon(cx, cy, 96, math.pi / 6)
        d.polygon(pts, outline=(*CYAN, 56), fill=(*CYAN, 8), width=2)
        for k in range(6):
            ang = k * math.pi / 3
            nx, ny = cx + 60 * math.cos(ang), cy + 60 * math.sin(ang)
            d.line([(cx, cy), (nx, ny)], fill=(*GREEN, 60), width=1)
            d.ellipse([nx - 3, ny - 3, nx + 3, ny + 3], fill=(*GREEN, 200))
    # Inter-cluster links.
    for i, a in enumerate(clusters):
        for b in clusters[i + 1:]:
            if rng.random() < 0.5:
                d.line([a, b], fill=(*CYAN, 40), width=1)
    img = compose(img, layer, blur=6, gain=1.2)
    img = particle_field(img, 23, 80, GREEN)
    img = corner_hud(img, GREEN)
    img = vignette(img, 0.68)
    save_webp(add_noise(img, 4), "network-visual.webp", 86)


def make_recon():
    w, h = 1600, 1000
    img = gradient_canvas(w, h, 31, GREEN, CYAN)
    img = fine_grid(img, (60, 120, 110), 26, 40)
    # Radar.
    cx, cy, r = w * 0.52, h * 0.53, h * 0.36
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for i in range(1, 7):
        rr = r * i / 6
        d.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], outline=(*GREEN, 44), width=1)
    d.line([(cx - r, cy), (cx + r, cy)], fill=(*GREEN, 50), width=1)
    d.line([(cx, cy - r), (cx, cy + r)], fill=(*GREEN, 50), width=1)
    d.pieslice([cx - r, cy - r, cx + r, cy + r], 300, 350, fill=(*GREEN, 24))
    for ang in (312, 336, 351):
        rad = math.radians(ang)
        d.line([(cx, cy), (cx + r * math.cos(rad), cy + r * math.sin(rad))], fill=(*CYAN, 65), width=1)
    rng = random.Random(9)
    for _ in range(22):
        a = rng.uniform(0, 2 * math.pi)
        rad = rng.uniform(0.1, 0.94) * r
        x, y = cx + rad * math.cos(a), cy + rad * math.sin(a)
        d.ellipse([x - 3, y - 3, x + 3, y + 3], fill=(*GREEN, rng.randint(80, 230)))
        if rng.random() < 0.45:
            d.line([(cx, cy), (x, y)], fill=(*GREEN, 22), width=1)
    img = compose(img, layer, blur=8, gain=1.25)
    # Signal card frame.
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    d.rounded_rectangle([w * 0.07, h * 0.12, w * 0.27, h * 0.38], 10, outline=(*GREEN, 100), width=1, fill=(*BG, 100))
    for i in range(7):
        d.rectangle([w * 0.09, h * (0.16 + i * 0.026), w * (0.11 + 0.1 * rng.random()), h * (0.168 + i * 0.026)], fill=(*GREEN, 70))
    img = compose(img, layer, blur=3, gain=0.9)
    img = corner_hud(img, GREEN)
    img = vignette(img, 0.72)
    save_webp(add_noise(img, 4), "recon-visual.webp", 86)


def make_threat_intel():
    w, h = 1600, 1000
    img = gradient_canvas(w, h, 44, CYAN, VIOLET)
    img = fine_grid(img, (80, 100, 160), 20, 44)
    img = wire_globe(img, w * 0.54, h * 0.47, h * 0.32, 17, CYAN)
    # Threat arcs across globe.
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    cx, cy = w * 0.54, h * 0.47
    for i in range(7):
        rr = h * (0.36 + i * 0.035)
        d.arc([cx - rr, cy - rr * 0.4, cx + rr, cy + rr * 0.4], 200 + i * 12, 340 - i * 8, fill=(*VIOLET, 40 + i * 10), width=2)
    # Malicious nodes + labeled-card geometry.
    rng = random.Random(7)
    for _ in range(14):
        x, y = rng.uniform(w * 0.2, w * 0.88), rng.uniform(h * 0.18, h * 0.8)
        col = RED if rng.random() < 0.28 else GREEN
        d.line([(cx, cy), (x, y)], fill=(*col, rng.randint(18, 56)), width=1)
        d.ellipse([x - 4, y - 4, x + 4, y + 4], fill=(*col, 220))
    # Floating intel cards.
    for i, (fx, fy) in enumerate([(0.1, 0.2), (0.1, 0.66), (0.78, 0.16), (0.79, 0.64)]):
        x, y = w * fx, h * fy
        d.rounded_rectangle([x, y, x + 250, y + 118], 10, outline=(*CYAN, 80), fill=(*BG, 160), width=1)
        d.rectangle([x, y, x + 4, y + 118], fill=(*GREEN, 160))
        for j in range(4):
            d.line([(x + 20, y + 25 + j * 20), (x + 20 + (135 if j % 2 == 0 else 90), y + 25 + j * 20)], fill=(*MUTED, 120), width=2)
    img = compose(img, layer, blur=9, gain=1.15)
    img = particle_field(img, 55, 70, VIOLET)
    img = corner_hud(img, VIOLET)
    img = vignette(img, 0.74)
    save_webp(add_noise(img, 4), "threat-intelligence.webp", 86)


def make_mitre():
    w, h = 1600, 1000
    img = gradient_canvas(w, h, 57, VIOLET, CYAN)
    # Matrix.
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    cols, rows = 8, 5
    x0, y0 = w * 0.09, h * 0.18
    cw, ch = w * 0.82 / cols, h * 0.54 / rows
    rng = random.Random(8)
    for c in range(cols):
        for r in range(rows):
            x, y = x0 + c * cw, y0 + r * ch
            active = rng.random()
            col = GREEN if active > 0.73 else (CYAN if active > 0.4 else VIOLET)
            alpha = 16 if active < 0.4 else 34 + int(active * 38)
            d.rounded_rectangle([x + 5, y + 5, x + cw - 5, y + ch - 5], 5, fill=(*col, alpha), outline=(*col, alpha + 28), width=1)
            if active > 0.63:
                d.rectangle([x + 14, y + 16, x + 14 + (cw - 42) * rng.uniform(0.25, 0.92), y + 20], fill=(*col, 120))
                d.line([(x + 14, y + 32), (x + cw - 20, y + 32)], fill=(*col, 45), width=1)
                d.line([(x + 14, y + 42), (x + 14 + (cw - 60) * rng.uniform(0.2, 0.8), y + 42)], fill=(*MUTED, 70), width=1)
    # Attack chain.
    chain = [(w * 0.13, h * 0.84), (w * 0.3, h * 0.76), (w * 0.47, h * 0.84), (w * 0.64, h * 0.75), (w * 0.82, h * 0.83)]
    for i in range(len(chain) - 1):
        d.line([chain[i], chain[i + 1]], fill=(*CYAN, 90), width=2)
    for i, (x, y) in enumerate(chain):
        d.ellipse([x - 9, y - 9, x + 9, y + 9], fill=(*BG, 255), outline=(*(GREEN if i < 3 else AMBER), 230), width=3)
    img = compose(img, layer, blur=10, gain=1.2)
    img = grid_scanlines(img, 34)
    img = corner_hud(img, VIOLET)
    img = vignette(img, 0.72)
    save_webp(add_noise(img, 5), "mitre-attack.webp", 86)


def grid_scanlines(img, alpha=24):
    layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    w, h = img.size
    for y in range(0, h, 4):
        d.line([(0, y), (w, y)], fill=(*CYAN, alpha // 3), width=1)
    return compose(img, layer, blur=0, gain=1)


def make_vulnerability():
    w, h = 1600, 1000
    img = gradient_canvas(w, h, 71, AMBER, VIOLET)
    img = fine_grid(img, (120, 90, 130), 22, 46)
    # Large hex shield.
    layer = Image.new("RGBA", w and (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    cx, cy = w * 0.43, h * 0.51
    shield = [(cx, cy - h * 0.33), (cx + w * 0.16, cy - h * 0.19), (cx + w * 0.13, cy + h * 0.15), (cx, cy + h * 0.32), (cx - w * 0.13, cy + h * 0.15), (cx - w * 0.16, cy - h * 0.19)]
    for i in range(len(shield)):
        a, b = shield[i], shield[(i + 1) % len(shield)]
        draw_gradient_line(d, a, b, CYAN, VIOLET, 3, 24)
    for i in range(1, 5):
        s = [ (cx + (p[0] - cx) * (1 - i * 0.12), cy + (p[1] - cy) * (1 - i * 0.12)) for p in shield]
        d.polygon(s, outline=(*VIOLET, 34), fill=(*VIOLET, 5))
    # Crack.
    crack = [(cx - w * 0.02, cy - h * 0.26), (cx + w * 0.03, cy - h * 0.1), (cx - w * 0.015, cy + h * 0.02), (cx + w * 0.035, cy + h * 0.12), (cx - w * 0.01, cy + h * 0.25)]
    for i in range(len(crack) - 1):
        d.line([crack[i], crack[i + 1]], fill=(*AMBER, 155), width=2)
        if i < 3:
            bx, by = crack[i + 1]
            d.line([(bx, by), (bx + w * 0.06, by - h * 0.035)], fill=(*AMBER, 80), width=1)
            d.line([(bx, by), (bx - w * 0.05, by + h * 0.025)], fill=(*AMBER, 65), width=1)
    # Severity distribution bars.
    for i, (col, val) in enumerate([(RED, 0.82), (AMBER, 0.56), (VIOLET, 0.42), (CYAN, 0.3)]):
        x = w * 0.7 + i * w * 0.058
        d.rounded_rectangle([x, h * (0.78 - val * 0.42), x + 24, h * 0.78], 4, fill=(*col, 40), outline=(*col, 90), width=1)
        d.rectangle([x, h * (0.78 - val * 0.42), x + 24, h * (0.78 - val * 0.42) + 4], fill=(*col, 220))
    # CVE scan lines.
    d.line([(w * 0.61, h * 0.22), (w * 0.61, h * 0.7)], fill=(*MUTED, 70), width=1)
    img = compose(img, layer, blur=9, gain=1.2)
    img = particle_field(img, 77, 65, AMBER)
    img = corner_hud(img, AMBER)
    img = vignette(img, 0.73)
    save_webp(add_noise(img, 4), "vulnerability-visual.webp", 86)


def make_osint():
    w, h = 1600, 1000
    img = gradient_canvas(w, h, 88, GREEN, VIOLET)
    img = fine_grid(img, (70, 110, 110), 18, 52)
    # Iris.
    cx, cy = w * 0.56, h * 0.48
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    rng = random.Random(19)
    for i in range(38):
        ang = rng.uniform(0, 2 * math.pi)
        r0 = h * rng.uniform(0.13, 0.2)
        r1 = h * rng.uniform(0.2, 0.38)
        d.line([(cx + r0 * math.cos(ang), cy + r0 * math.sin(ang)), (cx + r1 * math.cos(ang), cy + r1 * math.sin(ang))], fill=(*GREEN, rng.randint(40, 140)), width=rng.choice([1, 1, 2]))
    for r in [h * 0.12, h * 0.2, h * 0.29, h * 0.4]:
        d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=(*CYAN, 52), width=1)
    d.ellipse([cx - h * 0.085, cy - h * 0.085, cx + h * 0.085, cy + h * 0.085], fill=(*BG, 170), outline=(*GREEN, 120), width=2)
    # Data trace ribbons.
    for i in range(6):
        pts = []
        for j in range(40):
            x = w * (0.05 + j * 0.022)
            y = h * (0.77 + i * 0.018) + math.sin(j * 0.5 + i) * h * 0.012
            pts.append((x, y))
        d.line(pts, fill=(*CYAN, 30 + i * 10), width=1)
    # Evidence nodes.
    for _ in range(20):
        x, y = rng.uniform(w * 0.1, w * 0.9), rng.uniform(h * 0.16, h * 0.8)
        d.rectangle([x - 4, y - 4, x + 4, y + 4], outline=(*GREEN, 120), width=1)
    img = compose(img, layer, blur=9, gain=1.2)
    img = particle_field(img, 91, 80, GREEN)
    img = corner_hud(img, GREEN)
    img = vignette(img, 0.72)
    save_webp(add_noise(img, 4), "osint-visual.webp", 86)


def make_login_background():
    w, h = 1920, 1080
    img = gradient_canvas(w, h, 99, CYAN, VIOLET)
    img = perspective_grid(img, 1, 0.7, VIOLET, 36)
    img = fine_grid(img, (70, 90, 130), 12, 57)
    img = wire_globe(img, w * 0.72, h * 0.5, h * 0.3, 21, CYAN)
    img = hud_rings(img, w * 0.72, h * 0.5, h * 0.4, CYAN, 6)
    img = network_graph(img, 42, 22, 0.28, GREEN)
    img = particle_field(img, 98, 120)
    # Diagonal light sweep.
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for i in range(18):
        x = w * 0.05 + i * 22
        d.line([(x, h * 0.9), (x + w * 0.36, h * 0.06)], fill=(*VIOLET, 10), width=2)
    d.line([(0, h * 0.72), (w * 0.4, 0)], fill=(*CYAN, 24), width=1)
    # Matrix-sparse dots.
    rng = random.Random(12)
    for _ in range(70):
        x, y = rng.uniform(w * 0.02, w * 0.5), rng.uniform(h * 0.1, h * 0.9)
        d.line([(x, y), (x, y + rng.uniform(8, 32))], fill=(*GREEN, rng.randint(12, 40)), width=1)
    img = compose(img, layer, blur=8, gain=1.1)
    img = corner_hud(img, CYAN)
    img = vignette(img, 0.84)
    img = add_noise(img, 4)
    save_webp(img, "login-background.webp", 88)
    small = img.resize((960, 540), Image.LANCZOS)
    save_webp(small, "login-background-960.webp", 84)


def make_og():
    w, h = 1200, 630
    img = gradient_canvas(w, h, 111, CYAN, VIOLET)
    img = perspective_grid(img, 1, 0.7, CYAN, 30)
    img = hud_rings(img, w * 0.83, h * 0.5, h * 0.34, CYAN, 4)
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    draw_emblem(d, 145, h / 2, 150)
    f1 = font(FONT_MONO, 22)
    f2 = font(FONT_BOLD, 82)
    f3 = font(FONT_MONO, 17)
    spaced_text(d, (270, 232), "DARKBYTE", f1, (*GREEN, 230), 7)
    spaced_text(d, (266, 272), "ARES", f2, (*TEXT, 255), 1)
    spaced_text(d, (270, 376), "ONE FRAMEWORK. COMPLETE RED TEAM OPERATIONS.", f3, (*MUTED, 255), 1)
    d.line([(270, 360), (720, 360)], fill=(*CYAN, 90), width=1)
    img = compose(img, layer, blur=8, gain=1.1)
    img = vignette(img, 0.7)
    save_webp(add_noise(img, 3), "og-image.webp", 87)


def main():
    print("DARKBYTE ARES · generating original visual assets")
    make_logo()
    make_icon()
    make_hero()
    make_network()
    make_recon()
    make_threat_intel()
    make_mitre()
    make_vulnerability()
    make_osint()
    make_login_background()
    make_og()
    print(f"Assets written to {OUT}")


if __name__ == "__main__":
    main()
