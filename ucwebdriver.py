
from nodriver import Browser, start
import asyncio
from time import sleep, time
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from utils import get_useragent, http_get, save_html
from dotenv import load_dotenv
load_dotenv()

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
        self.browser = None
        self.page = None
        self.error = None
        self.user_agent = user_agent if user_agent else get_useragent()
        self.loop = asyncio.new_event_loop()

    def run_task(self, fn):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        task = loop.create_task(fn())
        loop.run_until_complete(task)
        result = task.result()
        return result

    def get_driver(self, **kwargs) -> Browser:
        headless = kwargs.get("headless", self.headless)
        user_agent = kwargs.get("user_agent", self.user_agent)
        browser_args = kwargs.get("browser_args", [])
        if not self.driver:
            async def _():
                if user_agent or headless:
                    browser_args.append(f"--user-agent={user_agent}")
                self.driver = await start(
                    headless=headless,
                    browser_args=browser_args,
                )
                return self.driver
            self.run_task(_)
            # print(dr)
            # page = await browser.get("https://www.chewy.com/")
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


    def html(self, url, **kwargs):
        timeout = kwargs.get("timeout", 3)
        wait_for = kwargs.get("wait_for", None)
        driver = self.get_driver(**kwargs)

        async def _():
            try:
                page = await driver.get(url)
                await page.sleep(timeout)
                if wait_for:
                    await page.wait_for(selector=wait_for, timeout=20)
                html = await page.get_content()
                return html
            finally:
                await page.close()
                driver.stop()

        return self.run_task(_)

    @classmethod
    def get_html(cls, url, **kwargs):
        html = ""
        use_browser = kwargs.get("use_browser", False)
        wait_for = kwargs.get("wait_for", False)
        headers = kwargs.get("headers", {})
        try:
            c = cls()
            if not use_browser and not wait_for:
                html = http_get(url, headers)
                if html:
                    return html
            html = c.html(url, **kwargs)
            er = c.in_str(html)
            if er:
                raise Exception(er)
            # html = {
            #     "success": True,
            #     "html": html
            # }
        except Exception as e:
            print("Get html error:", str(e))
            # html = {
            #     "success": False,
            #     "message": str(e)
            # }
        finally:
            c.close_driver()
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

    d = UC_Webdriver.get_html("https://www.chewy.com/bones-chews-made-in-usa-roasted/dp/363470",
                              headless=True, use_browser=True, wait_for=".chewy-logo")
    print(d)
