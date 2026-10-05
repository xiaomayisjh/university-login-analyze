"""Opt-in HTTP smoke test using synthetic images and the project's .env.

Run from the project root: python tests/anticap_smoke.py
This sends test images only to the configured captcha service, not login sites.
"""

from io import BytesIO
from pathlib import Path
import random
import sys

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from captcha_solver import CaptchaSolver, CaptchaSolverError


def png_bytes(image):
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def ocr_fixture():
    for font_name in ("DejaVuSans.ttf", "arial.ttf"):
        try:
            font = ImageFont.truetype(font_name, 48)
            image = Image.new("RGB", (220, 72), "white")
            ImageDraw.Draw(image).text((10, 4), "A7K9", fill="black", font=font)
            return png_bytes(image)
        except OSError:
            continue
    image = Image.new("RGB", (60, 20), "white")
    ImageDraw.Draw(image).text((4, 2), "A7K9", fill="black", font=ImageFont.load_default())
    return png_bytes(image.resize((240, 80)))


def slider_fixtures():
    # A known crop of a deterministic textured image tests original-pixel output.
    rng = random.Random(314521)
    background = Image.new("RGB", (240, 120))
    background.putdata([(rng.randrange(256), rng.randrange(256), rng.randrange(256)) for _ in range(240 * 120)])
    target = background.crop((127, 31, 167, 71)).convert("RGBA")
    return png_bytes(target), png_bytes(background)


def main():
    try:
        with CaptchaSolver() as solver:
            health = solver.session.get(solver.api_base_url + "/health", timeout=10, allow_redirects=False)
            health.raise_for_status()
            state = health.json()
            print("Health: status={}, ready={}".format(state.get("status"), state.get("ready")))
            if not state.get("ready"):
                raise RuntimeError("AntiCAP engine is not ready")

            text = solver.solve_image_captcha(image_data=ocr_fixture())
            print("OCR: {!r}; request_id={}".format(text, solver.last_meta.get("request_id")))
            # This smoke check verifies the characters; the client preserves
            # the exact case returned by the OCR service.
            if text.casefold() != "a7k9":
                raise RuntimeError("Synthetic OCR fixture mismatch: expected characters A7K9")

            target, background = slider_fixtures()
            match = solver.solve_slide_captcha(bg_image_data=target, slide_image_data=background)
            print("Slider: {}; request_id={}".format(match, solver.last_meta.get("request_id")))
            if abs(match["x"] - 127) > 2 or abs(match["target"][1] - 31) > 2:
                raise RuntimeError("Synthetic slider fixture mismatch: expected position (127, 31)")
            print("AntiCAP OCR and slider HTTP smoke tests passed")
        return 0
    except CaptchaSolverError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
