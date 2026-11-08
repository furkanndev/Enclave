"""
Enclave - Modern Uygulama Simgesi (Icon Generator)
Çoklu çözünürlükte (256, 128, 64, 48, 32, 16) şık bir Windows .ico dosyası üretir.
"""

from PIL import Image, ImageDraw

def generate_vault_icon():
    sizes = [256, 128, 64, 48, 32, 16]
    images = []

    for size in sizes:
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        pad = max(2, size // 16)
        r = size // 5
        
        draw.rounded_rectangle(
            [pad, pad, size - pad, size - pad],
            radius=r,
            fill=(99, 102, 241, 255),
            outline=(129, 140, 248, 255),
            width=max(1, size // 32)
        )

        cx = size // 2
        cy = size // 2
        
        arc_w = max(2, size // 14)
        arch_r = size // 5
        draw.arc(
            [cx - arch_r, cy - arch_r - size // 8, cx + arch_r, cy + arch_r - size // 8],
            start=180,
            end=0,
            fill=(255, 255, 255, 255),
            width=arc_w
        )

        body_w = size // 3
        body_h = size // 4
        draw.rounded_rectangle(
            [cx - body_w // 2, cy - size // 14, cx + body_w // 2, cy - size // 14 + body_h],
            radius=max(2, size // 20),
            fill=(255, 255, 255, 255)
        )

        hole_r = max(2, size // 18)
        draw.ellipse(
            [cx - hole_r, cy + size // 24 - hole_r, cx + hole_r, cy + size // 24 + hole_r],
            fill=(99, 102, 241, 255)
        )
        draw.rectangle(
            [cx - max(1, hole_r // 2), cy + size // 24, cx + max(1, hole_r // 2), cy + size // 24 + size // 12],
            fill=(99, 102, 241, 255)
        )

        images.append(img)

    images[0].save(
        "app_icon.ico",
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=images[1:]
    )
    print("app_icon.ico basariyla olusturuldu.")

if __name__ == "__main__":
    generate_vault_icon()
