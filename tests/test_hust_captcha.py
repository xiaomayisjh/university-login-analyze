import unittest
from io import BytesIO

from PIL import Image

from hust自动登录 import HUSTLogin, enhance_hust_captcha


def _animated_gif():
    frames = []
    for index in range(4):
        frame = Image.new("L", (12, 10), 255)
        for x in range(2, 5):
            for y in range(3, 6):
                frame.putpixel((x, y), 0)  # Stable character stroke across frames.
        for x in range(6, 9):
            for y in range(3, 6):
                frame.putpixel((x, y), 0)  # Stable character stroke across frames.
        frame.putpixel((index, 1), 0)  # Moving interference.
        frames.append(frame.convert("P"))
    output = BytesIO()
    frames[0].save(
        output,
        format="GIF",
        save_all=True,
        append_images=frames[1:],
        duration=100,
        loop=0,
    )
    return output.getvalue()


class HUSTCaptchaTests(unittest.TestCase):
    def test_animated_captcha_is_merged_and_normalized_to_single_png(self):
        result = enhance_hust_captcha(_animated_gif(), scale=2)

        with Image.open(BytesIO(result)) as image:
            self.assertEqual(image.format, "PNG")
            self.assertEqual(image.n_frames, 1)
            self.assertEqual(image.size, (24, 20))
            pixels = image.convert("L")
            self.assertLess(pixels.getpixel((6, 8)), 80)
            self.assertLess(pixels.getpixel((14, 8)), 80)

    def test_static_captcha_is_also_converted_to_single_png(self):
        source = BytesIO()
        Image.new("RGB", (8, 6), "white").save(source, format="JPEG")

        result = enhance_hust_captcha(source.getvalue(), scale=1)

        with Image.open(BytesIO(result)) as image:
            self.assertEqual(image.format, "PNG")
            self.assertEqual(image.n_frames, 1)
            self.assertEqual(image.size, (8, 6))

    def test_hust_personnel_not_found_is_classified_as_invalid_credentials(self):
        self.assertTrue(HUSTLogin._is_invalid_credentials("人员编号/学号不存在"))


if __name__ == "__main__":
    unittest.main()
