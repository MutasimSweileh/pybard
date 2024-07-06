
import random
from curl_cffi.requests import Session, get, post
from time import sleep, time
from threading import Thread
from json import loads, dumps
import undetected_chromedriver as uc
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from dotenv import load_dotenv
load_dotenv()

_useragent_list = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.62',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0'
]


class CustomUCWebDriver(uc.Chrome):
    def post(self, url, data):
        return self.execute_script(f"""
            return fetch("{url}", {{
                method: "POST",
                body: '{data}',
                headers: {{
                    "Content-Type": "text/plain;charset=UTF-8"
                }}
            }})
            .then(response => response.text());
        """)

    def get_useragent(self):
        """Returns a random user agent from the list."""
        return random.choice(_useragent_list)

    def user_agent(self):
        return self.execute_script("return window.navigator.userAgent;")

    def locator(self, locator, timeout=5):
        ba = By.CSS_SELECTOR
        if locator.find("[") == -1 and locator.find(".") == -1 and locator.find("(") == -1 and locator.find("#") == -1:
            ba = By.TAG_NAME
        try:
            el = self.find_element(
                ba, locator)
            return el
        except Exception as e:
            raise Exception(f"Element not found! {locator}")

    def wait_for_timeout(self, timeout=3000):
        timeout = (timeout / 1000) if timeout > 100 else timeout
        sleep(timeout)

    def goto(self, url):
        self.get(url)

    def content(self):
        return self.page_source

    def get_html(self, tag="body"):
        return self.find_element(By.TAG_NAME, tag).get_attribute('innerHTML')

    def get_text(self, tag="body"):
        return self.find_element(By.TAG_NAME, tag).text


class UC_Webdriver:
    def __init__(self, headless=True, user_agent=None):
        self.headless = headless
        self.driver = None
        self.user_agent = user_agent

    def get_driver(self, **kwargs) -> CustomUCWebDriver:
        headless = kwargs.get("headless", self.headless)
        user_agent = kwargs.get("user_agent", self.user_agent)
        if not self.driver:
            chrome_options = uc.ChromeOptions()
            service = Service()
            # service = Service(executable_path=ChromeDriverManager().install())
            driver_executable_path = ChromeDriverManager().install()
            # driver_executable_path = None
            # print(driver_executable_path)
            if headless:
                chrome_options.add_argument('--headless=new')
                chrome_options.add_argument("--headless")
                chrome_options.add_argument("--incognito")
                chrome_options.add_argument("--disable-application-cache")
                chrome_options.add_argument("--disable-setuid-sandbox")
                chrome_options.add_argument(
                    "--window-size=%s,%s" % (
                        1440, 1880
                    )
                )
            chrome_options.add_argument("--start-maximized")
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument("--disable-browser-side-navigation")
            chrome_options.add_argument("--disable-save-password-bubble")
            chrome_options.add_argument("--disable-single-click-autofill")
            chrome_options.add_argument("--allow-file-access-from-files")
            chrome_options.add_argument("--disable-prompt-on-repost")
            chrome_options.add_argument("--dns-prefetch-disable")
            chrome_options.add_argument("--disable-translate")
            chrome_options.add_argument(
                "--disable-backgrounding-occluded-windows")
            chrome_options.add_argument(
                "--disable-client-side-phishing-detection")
            chrome_options.add_argument("--disable-oopr-debug-crash-dump")
            chrome_options.add_argument("--disable-top-sites")
            chrome_options.add_argument("--ash-no-nudges")
            chrome_options.add_argument("--no-crash-upload")
            chrome_options.add_argument("--deny-permission-prompts")
            if user_agent:
                chrome_options.add_argument(f"--user-agent={user_agent}")
            self.driver = CustomUCWebDriver(
                headless=headless, use_subprocess=True, enable_cdp_events=True, options=chrome_options, driver_executable_path=driver_executable_path)

        return self.driver

    def in_str(self, string, arr=None, lower=True):
        if not string:
            return False
        if not arr:
            arr = [
                # "Something went wrong on our end",
                "Enter the characters you see below",
                "503 Service Unavailable",
                "Attention Required!",
                "We are checking your browser",
                "Your client does not have permission",
                "Our systems have detected unusual traffic",
                "Enter the characters you see below",
                "make sure you're not a robot",
                ".well-known/captcha",
            ]
        if not isinstance(arr, list):
            arr = [arr]
        for value in arr:
            if not value:
                continue
            if lower:
                string = string.lower()
                value = value.lower()
            if string.find(value) != -1 or value.find(string) != -1:
                return value
        return False

    def http_get(self, url, brower="chrome", headers={}):
        try:
            r = Session()
            r.headers.update(headers)
            r = r.get(url, impersonate=brower)
            if r.status_code == 200:
                html = r.text
                if not self.in_str(html):
                    return html
        except:
            pass
        return None

    @classmethod
    def get_html(cls, url, **kwargs):
        html = ""
        try:
            # c = cls()
            # html = c.dr.get_html(url, kwargs)
            # er = c.in_str(html)
            # if er:
            #     raise Exception(er)
            return None
        except Exception as e:
            print("Get html error:", str(e))
            html = ""
        # finally:
        #     c.close_driver()
        return html

    def driver_cookies(self):
        cookies = {}
        co = self.driver.get_cookies()
        self.d_cookies = co
        for c in co:
            cookies[c["name"]] = c["value"]
        return cookies

    def close_driver(self):
        if self.driver:
            try:
                self.driver.close()
                self.driver.quit()
                self.driver = None
            except:
                pass


            # print("close_driver!")
if __name__ == "__main__":
    d = UC_Webdriver.get_html("https://www.chewy.com/new-age-pet-ecoflex-mojave-reptile/dp/288127",
                              headless=False, use_browser=True, timeout=50000)
    print(d)
