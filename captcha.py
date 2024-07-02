
import numpy
import cv2
from PIL import Image, ImageFilter, ImageChops
import os
# import easyocr
from paddleocr import PaddleOCR
from twocaptcha import TwoCaptcha
from anticaptchaofficial.funcaptchaproxyless import *
from anticaptchaofficial.imagecaptcha import *
import config
# Defining paths to tesseract.exe
# and the image we would be using
path_to_tesseract = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
image_path = r"captcha.png"
# image_path = r"5983450874773504.jpeg"


class Captcha(TwoCaptcha):

    def __init__(self):
        self.two_captcha = True
        self.ocr = "PaddleOCR"
        self.error = None
        super().__init__(os.getenv("TwoCaptcha_API_KEY"))

    def huggingface(self, captcha_path="captcha.png"):
        API_URL = "https://api-inference.huggingface.co/models/microsoft/trocr-large-printed"
        HUGGINGFACE_TOKEN = os.getenv("HUGGINGFACE_TOKEN")
        headers = {
            "Authorization": f"Bearer {HUGGINGFACE_TOKEN}"}
        with open(captcha_path, "rb") as f:
            data = f.read()
        response = requests.post(API_URL, headers=headers, data=data)
        return response.json()

    def funCaptcha(self, js, url=None):
        js = json.loads(js)
        js["data"] = js.get("data", None)
        try:
            if self.two_captcha:
                result = self.funcaptcha(sitekey=js["pkey"],
                                         url=url,
                                         surl=js["surl"])
                result = result["code"]
            else:
                solver = funcaptchaProxyless()
                solver.set_key(os.getenv("ANTICaptcha_API_KEY"))
                solver.set_website_url(url)
                solver.set_website_key(js["pkey"])
                solver.set_js_api_domain(js["surl"])
                token = solver.solve_and_return_solution()
                if token != 0:
                    result = token
                else:
                    raise Exception(solver.error_code)
        except Exception as e:
            print("funCaptcha error:", str(e))
            self.error = str(e)
            return None
        else:
            print("Solved! code:", result)
            return result

    def save_image_from_url(self, image_url, save_path):
        try:
            # Send a GET request to the image URL
            if image_url.find("http") == -1:
                return image_url
            response = requests.get(image_url)
            save_path = f"{os.getcwd()}/{save_path}"
            # Check if the request was successful (status code 200)
            if response.status_code == 200:
                # Open a file in binary write mode
                with open(save_path, 'wb') as file:
                    # Write the content of the response (image data) to the file
                    file.write(response.content)
                # print(f"Image saved to {save_path}")
                return save_path
            else:
                print(
                    f"Failed to retrieve image. HTTP Status code: {response.status_code}")
        except Exception as e:
            print(f"An error occurred: {e}")
        return None

    def reCaptcha(self, js, url=None):
        if type(js) == str:
            js = json.loads(js)
        print("Solving reCaptcha ..", js["sitekey"])
        try:
            result = self.recaptcha(sitekey=js["sitekey"],
                                    url=url)
            result = result["code"]
        except Exception as e:
            print("reCaptcha error:", str(e))
            self.error = str(e)
            return None
        else:
            print("Solved! code:", result)
            return result

    def get_grayscale(self, image):
        img = cv2.imread(image)
        return cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # Thresholding or Binarization
    def thresholding(self, src):
        return cv2.threshold(src, 127, 255, cv2.THRESH_TOZERO)[1]

    def ocr_with_easy(self, img):
        pass
        # gray_scale_image = self.get_grayscale(img)
        # self.thresholding(gray_scale_image)
        # cv2.imwrite('image.png', gray_scale_image)
        # reader = easyocr.Reader(['en'], verbose=False)
        # bounds = reader.readtext('image.png', paragraph="False", detail=0)
        # bounds = ''.join(bounds).replace(
        #     " ", "").strip() if len(bounds) > 0 else None
        # return bounds

    def ocr_with_paddle(self, img):
        finaltext = ''
        ocr = PaddleOCR(lang='en', use_angle_cls=True, show_log=False)
        img = cv2.imread(img)
        result = ocr.ocr(img)
        if not result[0]:
            return None
        for i in range(len(result[0])):
            text = result[0][i][1][0]
            finaltext += ' ' + text
        return finaltext.strip()

    def ocr_solver(self, img):
        result = None
        if self.ocr == "PaddleOCR":
            result = self.ocr_with_paddle(img)
        if not result:
            result = self.ocr_with_easy(img)
        return result

    def binarize_image_using_opencv(self, captcha_path, binary_image_path=None):
        if not binary_image_path:
            binary_image_path = captcha_path
        img = cv2.imread(captcha_path)
        im_gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        (thresh, im_bw) = cv2.threshold(im_gray, 128,
                                        255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
        # although thresh is used below, gonna pick something suitable
        im_bw = cv2.threshold(im_gray, thresh, 255, cv2.THRESH_BINARY)[1]
        cv2.imwrite(binary_image_path, im_bw)
        return binary_image_path

    def preprocess_image_using_opencv(self, captcha_path):
        bin_image_path = self.binarize_image_using_opencv(captcha_path)

        im_bin = Image.open(bin_image_path)

        basewidth = 340  # in pixels
        wpercent = (basewidth/float(im_bin.size[0]))
        hsize = int((float(im_bin.size[1])*float(wpercent)))
        big = im_bin.resize((basewidth, hsize), Image.NEAREST)

        # tesseract-ocr only works with TIF so save the bigger image in that format
        ext = ".tif"
        tif_file = "input-NEAREST.tif"
        big.save(tif_file)

        return tif_file

    def normal_capcha(self, file: str = "captcha.png"):
        try:
            file = file.replace("data:image/svg+xml;base64,", "")
            file = self.save_image_from_url(file, "captcha.png")
            res = None
            if self.ocr:
                res = self.ocr_solver(file)
                print(f"{self.ocr}:", res)
            if not res:
                solver = imagecaptcha()
                solver.set_key(os.getenv("ANTICaptcha_API_KEY"))
                res = solver.solve_and_return_solution(file)
                if res == 0:
                    raise Exception(solver.error_code)
                print("Anticaptcha:", res)
            return res
        except Exception as e:
            print(str(e))
            self.error = str(e)
        return None

    def handle_requsts(self, *args, **kwargs):
        method = kwargs.get("type", "normal")
        js = kwargs.get("js")
        self.ocr = kwargs.get("model", "PaddleOCR")
        url = kwargs.get("url")
        if method == "reCaptcha":
            c = self.reCaptcha(js, url)
        elif method == "funCaptcha":
            c = self.funCaptcha(js, url)
        else:
            c = self.normal_capcha(url)
        if not c:
            raise Exception(self.error)
        return c


if __name__ == "__main__":
    c = Captcha()
    c = c.normal_capcha(image_path)
    print(c)
