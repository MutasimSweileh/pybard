# from curl_cffi import requests as curl
import base64
import json
import os
from typing import Iterable, Dict
from gmail import temp_mail
from os import listdir
from uuid import uuid4
from time import sleep, time
from threading import Thread
from json import loads, dumps
from random import getrandbits
from websocket import WebSocketApp
# from requests import Session, get, post
from curl_cffi.requests import Session, WebSocket, get, post
import cloudscraper
import undetected_chromedriver as uc
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from dotenv import load_dotenv
load_dotenv()


class CustomException(Exception):
    def __init__(self, message):
        self.message = message

    def getJSON(self):
        if type(self.message) is dict:
            return self.message
        return {'message': self.message, "success": False}

    def __str__(self):
        return self.getJSON()['message']


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
        # window.navigator.userAgent
        return self.execute_script("return window.navigator.userAgent;")


class Perplexity:
    def __init__(self, cookies: str = None, email: str = None, debug=False, use_driver=False) -> None:
        # self.session: Session = Session()
        self.csrfToken = None
        self.driver = None
        self.isLogin = False
        self.email: str = email
        self.use_driver = use_driver
        self.d_cookies = None
        self.user_agent: dict = {
            "User-Agent": "Ask/2.4.1/224 (iOS; iPhone; Version 17.1) isiOSOnMac/false", "X-Client-Name": "Perplexity-iOS"}
        self.user_agent = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        }
        # self.session.headers.update(self.user_agent)
        self.cookies = self.convert_session(cookies)
        self.row_cookies = self.cookies
        self.debug = debug
        self.session = self.get_session()
        self.ws = None
        self.last_message = None

        self.n: int = 1
        self.base: int = 420
        self.queue: list = []
        self.finished: bool = True
        self.last_uuid: str = None
        self.backend_uuid: str = None  # unused because we can't yet follow-up questions
        self.frontend_session_id: str = str(uuid4())
        self.tmpEmail = temp_mail(email, create=True)

    def get_driver(self, url, headless=True):
        if not self.driver:
            chrome_options = uc.ChromeOptions()
            service = Service(executable_path=ChromeDriverManager().install())
            user_agent = self.user_agent["User-Agent"]
            # user_agent = None
            # chrome_options.add_argument("start-maximized")
            if headless:
                chrome_options.add_argument('--headless=new')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--no-sandbox')
            if user_agent:
                chrome_options.add_argument(f"--user-agent={user_agent}")
            self.driver = CustomUCWebDriver(
                headless=headless, use_subprocess=False, options=chrome_options, service=service)
        self.driver.get(url)
        self.user_agent["User-Agent"] = self.driver.user_agent()
        return self.driver.find_element(By.TAG_NAME, 'body').text

    def driver_cookies(self):
        cookies = {}
        co = self.driver.get_cookies()
        self.d_cookies = co
        for c in co:
            cookies[c["name"]] = c["value"]
        return cookies

    def _get_cookies(self, di=False):
        if self.use_driver and self.d_cookies:
            cookies = {}
            for c in self.d_cookies:
                cookies[c["name"]] = c["value"]
            if di:
                return cookies
            return self.d_cookies
        return self.session.cookies.get_dict()

    def close_driver(self):
        if self.driver:
            self.driver.close()
            self.driver = None

    def create_account(self):
        if not self.isLogin and self.email and not self.use_driver:
            self.copilot = 5
            self.file_upload = 3
            try:
                email = self.tmpEmail.getEmail(None)
                self.email = email
                resp = self.session.post('https://www.perplexity.ai/api/auth/signin-email', data={
                    'email': email,
                }, impersonate="chrome")
                if self.debug:
                    print(resp.status_code, resp.text)
                if resp.status_code == 200:
                    new_msgs = self.tmpEmail.getMessages(
                        "team@mail.perplexity.ai", wait=True)
                    if not new_msgs:
                        raise Exception(
                            f'Fail to get email message {self.email} !')
                    new_account_link = new_msgs[0]
                    self.session.get(new_account_link, impersonate="chrome")
                elif resp.status_code == 429:
                    raise Exception(
                        f'Too many requests. Try again in 1 minute.')
                else:
                    raise Exception(
                        f'Perplexity account creating error: Error triggering email sign in')
            except Exception as e:
                raise Exception(str(e))
        self.t: str = self._get_t()
        self.sid: str = self._get_sid()
        self._ask_anonymous_user()

        self.ws: WebSocketApp = self._init_websocket()
        self.ws_thread: Thread = Thread(target=self.ws.run_forever).start()
        # self._auth_session()

        while not (self.ws.sock and self.ws.sock.connected):
            sleep(0.01)
        return True

    def get_session(self) -> Session:
        self.session = Session()
        self.session.headers.update(self.user_agent)
        # self.session = cloudscraper.create_scraper(
        #     sess=self.session,
        #     debug=self.debug,
        #     delay=20,
        #     interpreter='js2py',
        #     captcha={
        #         'provider': '2captcha',
        #         'api_key': os.getenv("TwoCaptcha_API_KEY")
        #     }
        # )
        # self.session = curl.Session()
        try:
            if self.cookies:
                # del self.cookies["__Secure-next-auth.callback-url"]
                cookies = {}
                if type(self.cookies) is list:
                    for c in self.cookies:
                        cookies[c["name"]] = c["value"]
                else:
                    cookies = self.cookies
                self.session.cookies.update(cookies)
                self.csrfToken = cookies.get(
                    "next-auth.csrf-token", self.csrfToken)
            if not self._auth_session():
                self.isLogin = False
                self._init_session_without_login()
            else:
                self.isLogin = True
            cookies = self.get_cookies_dict()
            self.csrfToken = cookies.get(
                "next-auth.csrf-token", self.csrfToken)
            if self.csrfToken:
                self.csrfToken = self.csrfToken.split('%')[0]
            return self.session
        except Exception as e:
            m = str(e)
            print("get_session:", m)
            raise CustomException(m)

    def get_cookies_dict(self):
        cookies = {}
        for k, v in self.session.cookies.items():
            cookies[k] = v
        return cookies

    def convert_session(self, cookies):
        try:
            cookies = base64.b64decode(cookies).decode("utf-8")
        except:
            pass
        try:
            if cookies and type(cookies) is str:
                cookies = json.loads(cookies)
        except Exception as e:
            raise CustomException("Invalid session!")
        return cookies

    def _recover_session(self, email: str) -> None:
        with open(".perplexity_session", "r") as f:
            perplexity_session: dict = loads(f.read())

        if email in perplexity_session:
            self.session.cookies.update(perplexity_session[email])
        else:
            self._login(email, perplexity_session)

    def _login(self, email: str, ps: dict = None) -> None:
        self.session.post(
            url="https://www.perplexity.ai/api/auth/signin-email", data={"email": email})

        email_link: str = str(input("paste the link you received by email: "))
        self.session.get(email_link)

        if ps:
            ps[email] = self.session.cookies.get_dict()
        else:
            ps = {email: self.session.cookies.get_dict()}

        with open(".perplexity_session", "w") as f:
            f.write(dumps(ps))

    def _init_session_without_login(self) -> None:
        url = f"https://www.perplexity.ai/search/{str(uuid4())}"
        if not self.use_driver:
            re = self.session.get(
                url=url, impersonate="chrome")
            if self.debug:
                print(re.request.headers)
                print(re.request.url)
                print(re.status_code, re.text)
        else:
            self.get_driver(url)
            self.session.cookies.update(self.driver_cookies())
            user_agent = self.driver.user_agent()
            self.user_agent = {
                "User-Agent": user_agent}
            # print(self.user_agent)
            self.session.headers.update(self.user_agent)

    def _auth_session(self) -> None:
        if not self.cookies:
            return False
        re = self.session.get(
            url="https://www.perplexity.ai/api/auth/session", impersonate="chrome")
        if self.debug:
            print(re.request.url)
            print(re.status_code, re.text)
        if re.status_code == 200:
            # for k, v in re.headers.items():
            #     self.user_agent[k] = v
            # self.session.headers.update(self.user_agent)
            return re.json()
        return False

    def _get_t(self) -> str:
        return format(getrandbits(32), "08x")

    def _get_sid(self) -> str:
        if self.use_driver:
            j = self.get_driver(
                f"https://www.perplexity.ai/socket.io/?EIO=4&transport=polling&t={self.t}")
        else:
            re = self.session.get(
                url=f"https://www.perplexity.ai/socket.io/?EIO=4&transport=polling&t={self.t}", impersonate="chrome"
            )
            j = re.text
            if self.debug:
                print(re.request.url)
                print(re.status_code, re.text)
            if re.status_code != 200:
                raise Exception(
                    f"invalid session status_code: {re.status_code}")
        return loads(j[1:])["sid"]

    def _ask_anonymous_user(self) -> bool:
        if self.use_driver:
            response = self.driver.post(
                f"https://www.perplexity.ai/socket.io/?EIO=4&transport=polling&t={self.t}&sid={self.sid}", "40{\"jwt\":\"anonymous-ask-user\"}")
            cookies = self.driver_cookies()
            self.session.cookies.update(cookies)
            self.close_driver()
        else:
            response = self.session.post(
                url=f"https://www.perplexity.ai/socket.io/?EIO=4&transport=polling&t={self.t}&sid={self.sid}",
                data="40{\"jwt\":\"anonymous-ask-user\"}", impersonate="chrome"
            )
            if self.debug:
                print(response.request.url)
                print(response.status_code, response.text)
            for k, v in response.headers.items():
                self.user_agent[k] = v
            # print(self.user_agent)
            response = response.text
        if response != "OK":
            raise Exception(
                "invalid session")
        return True

    def _start_interaction(self) -> None:
        self.finished = False

        if self.n == 9:
            self.n = 0
            self.base *= 10
        else:
            self.n += 1

        self.queue = []

    def _get_cookies_str(self) -> str:
        cookies = ""
        for key, value in self.get_cookies_dict().items():
            cookies += f"{key}={value}; "
        return cookies[:-2]

    def _write_file_url(self, filename: str, file_url: str) -> None:
        if ".perplexity_files_url" in listdir():
            with open(".perplexity_files_url", "r") as f:
                perplexity_files_url: dict = loads(f.read())
        else:
            perplexity_files_url: dict = {}

        perplexity_files_url[filename] = file_url

        with open(".perplexity_files_url", "w") as f:
            f.write(dumps(perplexity_files_url))

    def _init_websocket(self) -> WebSocketApp:
        def on_open(ws: WebSocketApp) -> None:
            ws.send("2probe")
            ws.send("5")

        def on_message(ws: WebSocketApp, message: str) -> None:
            self.last_message = message
            if message == "2":
                ws.send("3")
            elif message == '3probe':
                ws.send('5')
            elif not self.finished:
                if message.startswith("42"):
                    message: list = loads(message[2:])
                    content: dict = message[1]
                    if "mode" in content and content["mode"] == "copilot":
                        content["copilot_answer"] = loads(content["text"])
                    elif "mode" in content:
                        content.update(loads(content["text"]))
                    content.pop("text")
                    if (not ("final" in content and content["final"])) or ("status" in content and content["status"] == "completed"):
                        self.queue.append(content)
                    if message[0] == "query_answered":
                        self.last_uuid = content["uuid"]
                        self.finished = True
                elif message.startswith("43"):
                    message: dict = loads(message[3:])[0]
                    if message["step_type"] == "PROMPT_INPUT":
                        self.prompt_input(content)
                    elif ("uuid" in message and message["uuid"] != self.last_uuid) or "uuid" not in message:
                        self.queue.append(message)
                        self.finished = True

        return WebSocketApp(
            url=f"wss://www.perplexity.ai/socket.io/?EIO=4&transport=websocket&sid={self.sid}",
            header=self.user_agent,
            cookie=self._get_cookies_str(),
            on_open=on_open,
            on_message=on_message,
            on_error=lambda ws, err: print(f"websocket error: {err}")
        )

    def prompt_input(self, _last_answer, solvers={}):
        query = _last_answer["query_str"]
        self.backend_uuid = _last_answer['backend_uuid']
        focus = _last_answer['search_focus']
        for step_query in _last_answer['text'][-1]['content']['inputs']:
            if step_query['type'] == 'PROMPT_TEXT':
                solver = solvers.get('text', None)
                if solver:
                    self.ws.send(f'{self.base + self.n}' + json.dumps([
                        'perplexity_step',
                        query,
                        {
                            'version': '2.1',
                            'source': 'default',
                            'attachments': _last_answer['attachments'],
                            'last_backend_uuid': self.backend_uuid,
                            'existing_entry_uuid': self.backend_uuid,
                            'read_write_token': '',
                            'search_focus': focus,
                            'frontend_uuid': self.frontend_session_id,
                            'step_payload': {
                                'uuid': str(uuid4()),
                                'step_type': 'USER_INPUT',
                                'content': [{'content': {'text': solver(step_query['content']['description'])[:2000]}, 'type': 'USER_TEXT', 'uuid': step_query['uuid']}]
                            }
                        }
                    ]))
                else:
                    self.ws.send(f'{self.base + self.n}' + json.dumps([
                        'perplexity_step',
                        query,
                        {
                            'version': '2.1',
                            'source': 'default',
                            'attachments': _last_answer['attachments'],
                            'last_backend_uuid': self.backend_uuid,
                            'existing_entry_uuid': self.backend_uuid,
                            'read_write_token': '',
                            'search_focus': focus,
                            'frontend_uuid': self.frontend_session_id,
                            'step_payload': {
                                'uuid': str(uuid4()),
                                'step_type': 'USER_SKIP',
                                'content': [{'content': {'text': 'Skipped'}, 'type': 'USER_TEXT', 'uuid': step_query['uuid']}]
                            }
                        }
                    ]))

            if step_query['type'] == 'PROMPT_CHECKBOX':
                solver = solvers.get('checkbox', None)
                if solver:
                    solver_answer = solver(step_query['content']['description'], {int(
                        x['id']): x['value'] for x in step_query['content']['options']})

                    self.ws.send(f'{self.base + self.n}' + json.dumps([
                        'perplexity_step',
                        query,
                        {
                            'version': '2.1',
                            'source': 'default',
                            'attachments': _last_answer['attachments'],
                            'last_backend_uuid': self.backend_uuid,
                            'existing_entry_uuid': self.backend_uuid,
                            'read_write_token': '',
                            'search_focus': focus,
                            'frontend_uuid': self.frontend_session_id,
                            'step_payload': {
                                'uuid': str(uuid4()),
                                'step_type': 'USER_INPUT',
                                'content': [{'content': {'options': [x for x in step_query['content']['options'] if int(x['id']) in solver_answer]}, 'type': 'USER_CHECKBOX', 'uuid': step_query['uuid']}]
                            }
                        }
                    ]))
                else:
                    self.ws.send(f'{self.base + self.n}' + json.dumps([
                        'perplexity_step',
                        query,
                        {
                            'version': '2.1',
                            'source': 'default',
                            'attachments': _last_answer['attachments'],
                            'last_backend_uuid': self.backend_uuid,
                            'existing_entry_uuid': self.backend_uuid,
                            'read_write_token': '',
                            'search_focus': focus,
                            'frontend_uuid': self.frontend_session_id,
                            'step_payload': {
                                'uuid': str(uuid4()),
                                'step_type': 'USER_SKIP',
                                'content': [{'content': {'options': []}, 'type': 'USER_CHECKBOX', 'uuid': step_query['uuid']}]
                            }
                        }
                    ]))

    def _s(self, query: str, mode: str = "concise", focus: str = "internet", attachments: list[str] = [], language: str = "en-GB", in_page: str = None, in_domain: str = None) -> None:

        if not self.finished:
            raise Exception(
                "already searching")
        if len(attachments) >= 4:
            raise Exception(
                "too many attachments: max 4")
        if mode not in ['concise',
                        'copilot']:
            raise Exception(
                'Search modes --> ["concise", "copilot"]')
        if focus not in ['internet', 'scholar', 'writing', 'wolfram', 'youtube',
                         'reddit']:
            raise Exception(
                'Search focus modes --> ["internet", "scholar", "writing", "wolfram", "youtube", "reddit"]')
        # if ai_model not in ['default', 'experimental', 'gpt-4', 'claude-2.1',
        #                     'gemini pro']:
        #     raise Exception(
        #         'Ai models --> ["default", "experimental", "gpt-4", "claude-2.1", "gemini pro"]')
        if in_page:
            focus = "in_page"
        if in_domain:
            focus = "in_domain"

        self._start_interaction()
        ws_message: str = f"{self.base + self.n}" + dumps([
            "perplexity_ask",
            query,
            {
                "version": "2.1",
                "source": "default",  # "ios"
                "frontend_session_id": self.frontend_session_id,
                "language": language,
                "timezone": "CET",
                "attachments": attachments,
                "search_focus": focus,
                "frontend_uuid": str(uuid4()),
                "mode": mode,
                # "use_inhouse_model": True
                "in_page": in_page,
                "in_domain": in_domain
            }
        ])

        self.ws.send(ws_message)

    def search(self, query: str, mode: str = "concise", focus: str = "internet", attachments: list[str] = [], language: str = "en-GB", timeout: float = 30, in_page: str = None, in_domain: str = None) -> Iterable[Dict]:
        try:
            self._s(query, mode, focus, attachments,
                    language, in_page, in_domain)

            start_time: float = time()
            while (not self.finished) or len(self.queue) != 0:
                if timeout and time() - start_time > timeout:
                    self.finished = True
                    raise Exception("timeout")
                if len(self.queue) != 0:
                    yield self.queue.pop(0)
            return self.queue.pop(-1)
        except Exception as e:
            raise CustomException(str(e))

    def search_sync(self, query: str, mode: str = "concise", focus: str = "internet", attachments: list[str] = [], language: str = "en-GB", timeout: float = 30, in_page: str = None, in_domain: str = None) -> dict:
        try:
            self.create_account()
            self._s(query, mode, focus, attachments,
                    language, in_page, in_domain)

            start_time: float = time()
            while not self.finished:
                if timeout and time() - start_time > timeout:
                    self.finished = True
                    raise Exception(
                        f"timeout & last message: {self.last_message}")
            re = self.queue.pop(-1)
            try:
                re['text'] = json.loads(re['text'])
                if "answer" not in re['text']:
                    answer = json.loads(re["text"][-1]["content"]["answer"])
                    re['text'] = answer
                del re["text"]["chunks"]
                re["cookies"] = self.get_cookies_dict()
                re["email"] = self.email
                re["query_count_copilot"] = 5
            except Exception as es:
                raise Exception(
                    f"get answer error: {str(es)} & last json: {str(re)} & last message: {self.last_message}")
            return re
        except Exception as e:
            raise CustomException(str(e))
        finally:
            self.close()

    def upload(self, filename: str) -> str:
        assert self.finished, "already searching"
        assert filename.split(".")[-1] in ["txt", "pdf"], "invalid file format"

        if filename.startswith("http"):
            file = get(filename).content
        else:
            with open(filename, "rb") as f:
                file = f.read()

        self._start_interaction()
        ws_message: str = f"{self.base + self.n}" + dumps([
            "get_upload_url",
            {
                "version": "2.1",
                "source": "default",
                "content_type": "text/plain" if filename.split(".")[-1] == "txt" else "application/pdf",
            }
        ])

        self.ws.send(ws_message)

        while not self.finished or len(self.queue) != 0:
            if len(self.queue) != 0:
                upload_data = self.queue.pop(0)

        assert not upload_data["rate_limited"], "rate limited"

        post(
            url=upload_data["url"],
            files={
                "acl": (None, upload_data["fields"]["acl"]),
                "Content-Type": (None, upload_data["fields"]["Content-Type"]),
                "key": (None, upload_data["fields"]["key"]),
                "AWSAccessKeyId": (None, upload_data["fields"]["AWSAccessKeyId"]),
                "x-amz-security-token": (None, upload_data["fields"]["x-amz-security-token"]),
                "policy": (None, upload_data["fields"]["policy"]),
                "signature": (None, upload_data["fields"]["signature"]),
                "file": (filename, file)
            }
        )

        file_url: str = upload_data["url"] + \
            upload_data["fields"]["key"].split("$")[0] + filename

        self._write_file_url(filename, file_url)

        return file_url

    def threads(self, query: str = None, limit: int = None) -> list[dict]:
        assert self.email, "not logged in"
        assert self.finished, "already searching"

        if not limit:
            limit = 20
        data: dict = {"version": "2.1", "source": "default",
                      "limit": limit, "offset": 0}
        if query:
            data["search_term"] = query

        self._start_interaction()
        ws_message: str = f"{self.base + self.n}" + dumps([
            "list_ask_threads",
            data
        ])

        self.ws.send(ws_message)

        while not self.finished or len(self.queue) != 0:
            if len(self.queue) != 0:
                return self.queue.pop(0)

    def list_autosuggest(self, query: str = "", search_focus: str = "internet") -> list[dict]:
        assert self.finished, "already searching"

        self._start_interaction()
        ws_message: str = f"{self.base + self.n}" + dumps([
            "list_autosuggest",
            query,
            {
                "has_attachment": False,
                "search_focus": search_focus,
                "source": "default",
                "version": "2.1"
            }
        ])

        self.ws.send(ws_message)

        while not self.finished or len(self.queue) != 0:
            if len(self.queue) != 0:
                return self.queue.pop(0)

    def close(self) -> None:
        if self.ws:
            self.ws.close()
        self.close_driver()

        # if self.email:
        #     with open(".perplexity_session", "r") as f:
        #         perplexity_session: dict = loads(f.read())

        #     perplexity_session[self.email] = self.session.cookies.get_dict()

        #     with open(".perplexity_session", "w") as f:
        #         f.write(dumps(perplexity_session))


# email = "pefecu.jiyujori@theglossylocks.com"
# email = "wu.matarice@everysimply.com"
# cookies = "eyJBV1NBTEIiOiJcL3BYbWNMRWN6TmQ1cHhsQjI5NTdTT3M0REUzNUJYd2FKTVwvSSs4RCttbHF1WlJZd3dtR1JLandrT2N3TXYzNmxENldvVkxOa3pxc0x0THJWSUo1bFg4N2IzZCszSkM4XC9UYVdHcUNadWdSeU84UFhDTXZUT1JDWFVLck90RTZKTkxLZ2tzQkVSMkhmWllab3hwWWNzSEVoWXREam80MlJlTWltQ2xsMTZKdm1VZTN6SHFtcVwvWENEek5VcWlIdz09IiwiQVdTQUxCQ09SUyI6IlwvcFhtY0xFY3pOZDVweGxCMjk1N1NPczRERTM1Qlh3YUpNXC9JKzhEK21scXVaUll3d21HUktqd2tPY3dNdjM2bEQ2V29WTE5renFzTHRMclZJSjVsWDg3YjNkKzNKQzhcL1RhV0dxQ1p1Z1J5TzhQWENNdlRPUkNYVUtyT3RFNkpOTEtna3NCRVIySGZaWVpveHBZY3NIRWhZdERqbzQyUmVNaW1DbGwxNkp2bVVlM3pIcW1xXC9YQ0R6TlVxaUh3PT0iLCJfX1NlY3VyZS1uZXh0LWF1dGguY2FsbGJhY2stdXJsIjoiaHR0cHMlM0ElMkYlMkZ3d3cucGVycGxleGl0eS5haSUyRmFwaSUyRmF1dGglMkZzaWduaW4tY2FsbGJhY2slM0ZyZWRpcmVjdCUzRGRlZmF1bHRNb2JpbGVTaWduSW4iLCJfX1NlY3VyZS1uZXh0LWF1dGguc2Vzc2lvbi10b2tlbiI6ImV5SmhiR2NpT2lKa2FYSWlMQ0psYm1NaU9pSkJNalUyUjBOTkluMC4uX1IxZ09yTEJRZjFEcHlUMS45MzR3NzRzYlg5WkxxM1N2aDRXbzRmQ3V4RVJxTjgxMFlJdHFMdUxOblhmSnA1NjdvNGZYZ0I1TDhPUUdIbVdXS0hlY3I3ZFJfbU1wVFhJQV9FcFd2X3dkSXJOb0ZoeXZod1I0VEFSQTFJV1ZKRmhrdUlEbmduNWthV0l0ZC1hY0pVV25HMWZ6dHlDVHJNeHNYRUw4dXRvcG92dUxuVjRKQXREV29Yc29TRllfT2lWVDlhUlhqUW5oQlFhM2I0NERhdEpIVS1RVFVDdFlQMkxzNnRrVGFMRFEzUS5Udi0zeG56M3pTNklyWlVaOHVNdkN3IiwiX19jZl9ibSI6Ijh3WWRkZkRQVnhPUWIuQzBDVTFSQkxYemdYMVJkNDFCcmRnNUtEVEM2Tm8tMTcxMzQ0ODE1MC0xLjAuMS4xLUVRc0FwNTNzZVYwZklxbmJ6RGFxRjdUZlVwLlYwR1NYQ2pNWUpLbTJwcnpVRFJzNzVWN194bHo3NUNYYVZHel85Ql9HXzg1RzNZUzgwRlZZYmRrYlZnIiwiX19jZmxiIjoiMDJEaXVEeXZGTW1LNXA5alZiVm5NTlNLWVpoVUw5YUdtSjVabTFEQWhSY244IiwibmV4dC1hdXRoLmNzcmYtdG9rZW4iOiI2ZDU4ZWM0ZjIzZDMyMmZkODIyOTIyNGUzZGU0NmRmNzc1NzI5NWJiM2VmNTVjOTVlYmU5NDExODFjOGQzNjQyJTdDZjhjOTYyMWY1NmYwNjRjZjFmYTE4ZDNlZDA2Yjg2ZWY5MzBhM2ViNWJiMzhmNThlNGNkZWQ2YTM0Mzg1MjExMiJ9"
# cookies = [{'domain': 'www.perplexity.ai', 'expiry': 1714123777, 'httpOnly': False, 'name': 'AWSALBCORS', 'path': '/', 'sameSite': 'None', 'secure': True, 'value': 'qU/l4kh0+V8n/9Oji0kUCUWqgbJxGqt/kdCVRuO9hV/uxae4H98iwUZRHLQ5yH3mQSi5hr160+0HaYzTdtB/d14DC37mpQ6HPUuhxuaGlqKU9dor4JWz5j64sfUuAfssSNKhtRsqcvrGPcB4BB9pqr11drGEe+Sjd9cM6y4yNXrH8dpeTumwCyxcl2eGCg=='}, {'domain': 'www.perplexity.ai', 'expiry': 1714123777, 'httpOnly': False, 'name': 'AWSALB', 'path': '/', 'sameSite': 'Lax', 'secure': False, 'value': 'qU/l4kh0+V8n/9Oji0kUCUWqgbJxGqt/kdCVRuO9hV/uxae4H98iwUZRHLQ5yH3mQSi5hr160+0HaYzTdtB/d14DC37mpQ6HPUuhxuaGlqKU9dor4JWz5j64sfUuAfssSNKhtRsqcvrGPcB4BB9pqr11drGEe+Sjd9cM6y4yNXrH8dpeTumwCyxcl2eGCg=='}, {'domain': '.perplexity.ai', 'expiry': 1748078966, 'httpOnly': False, 'name': '_ga_SH9PRBQG23', 'path': '/', 'sameSite': 'Lax', 'secure': False, 'value': 'GS1.1.1713518966.1.0.1713518966.0.0.0'}, {'domain': 'www.perplexity.ai', 'expiry': 1745054966, 'httpOnly': False, 'name': 'pplx.visitor-id', 'path': '/', 'sameSite': 'Lax', 'secure': False, 'value': 'a91a8d48-6af5-4ecc-b7ce-423943b3d3ed'}, {'domain': 'www.perplexity.ai', 'expiry': 1748078965, 'httpOnly': False, 'name': 'isCollapsed', 'path': '/', 'sameSite': 'Lax', 'secure': False,
#                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                'value': 'false'}, {'domain': '.perplexity.ai', 'expiry': 1748078966, 'httpOnly': False, 'name': '_ga', 'path': '/', 'sameSite': 'Lax', 'secure': False, 'value': 'GA1.1.646725989.1713518967'}, {'domain': '.perplexity.ai', 'expiry': 1713520765, 'httpOnly': True, 'name': '__cf_bm', 'path': '/', 'sameSite': 'None', 'secure': True, 'value': 'hVbyKqCQsag2E_73ToFMrTsmzs5v0j5lKVqYBAw.7e0-1713518968-1.0.1.1-9wx3AbQdNrg1gcqKt8JcCr0NAwoH9yIVMZlBK2hlycr6ssnJMl9Sxhj9l.j1o5lbwTPyxGuQMvd2sB8A_RY84A'}, {'domain': 'www.perplexity.ai', 'httpOnly': True, 'name': '__Secure-next-auth.callback-url', 'path': '/', 'sameSite': 'Lax', 'secure': True, 'value': 'https%3A%2F%2Fwww.perplexity.ai%2Fapi%2Fauth%2Fsignin-callback%3Fredirect%3Dhttps%253A%252F%252Fwww.perplexity.ai'}, {'domain': 'www.perplexity.ai', 'expiry': 1713601765, 'httpOnly': True, 'name': '__cflb', 'path': '/', 'sameSite': 'None', 'secure': True, 'value': '02DiuDyvFMmK5p9jVbVnMNSKYZhUL9aGmjJHN9qoT8n1z'}, {'domain': 'www.perplexity.ai', 'httpOnly': True, 'name': 'next-auth.csrf-token', 'path': '/', 'sameSite': 'None', 'secure': True, 'value': '34eaf324f385f7198a1f4194d99ea686b3ee15328deb1e8260197eb3e7a1e6c3%7Caf9701678791a68a6e8e5d9b9fd3158905b42f74b0398fe3b068172dc1300a19'}]


email = "wu.matarice@everysimply.com"
# cookies = {'AWSALB': '3tVrdmNqYBuIbQJX51ZBAHbfg66ZvNagJF88on1eW/j1WjsqrtCkIpKyNXvSTqojDyvs2GCt8RUccw7lRm8tvgDGn4lYAEcjxQI6cwpziAd22840XTRoFYbk1co0HExVvNCz9JErMOFn8Zn7nRuw4ikabZa/YqRWeWIoOXz7v1IpX7bZHpa1IcuKDVfFlw==', 'AWSALBCORS': '3tVrdmNqYBuIbQJX51ZBAHbfg66ZvNagJF88on1eW/j1WjsqrtCkIpKyNXvSTqojDyvs2GCt8RUccw7lRm8tvgDGn4lYAEcjxQI6cwpziAd22840XTRoFYbk1co0HExVvNCz9JErMOFn8Zn7nRuw4ikabZa/YqRWeWIoOXz7v1IpX7bZHpa1IcuKDVfFlw==', 'next-auth.csrf-token': '2b13b47612a9ed3bddec1de8659d6b7764e479baee48b00171c08a5b956973bb%7Cc810c6bf74beafd263f715d275d754af29dba7cf113844049feef4be4d5aba4f', '__Secure-next-auth.callback-url': 'https%3A%2F%2Fwww.perplexity.ai%2Fapi%2Fauth%2Fsignin-callback%3Fredirect%3Dhttps%253A%252F%252Fwww.perplexity.ai', '__cflb': '02DiuDyvFMmK5p9jVbVnMNSKYZhUL9aGmEEcFk2EXiVDv', '__cf_bm': 'xVIMi6MRNGNxDnvAl_yZ4Zh3gwhNtsPctE.9Cr3daEs-1713556049-1.0.1.1-4JyyMVAkUg.KPkseJVaPsNYcKcwknh8k1gwtNNZ6Lcupxxj1ppeejHZQmp_sx7DqKP05dxazNpOS26E62YinZA'}
cookies = {'AWSALB': 'L8o8k2jA+1jzi2jN5nhpjJ6A7YduMOS0jBhnGvV4jg0gAKDB1vqvBsWcQMCOdiqtKpjEcNSBoMHudGwiGdrpofv2PFLWjPCII8DuJtr/JiUkymBNZXWRTDLpZcTeQi6AUtqgE2suw8rZTXrlaZ2Dq6vFqX4/0Q1cXMojXOoei8LyrdSoasxqvv+xUQk3kQ==', 'AWSALBCORS': 'L8o8k2jA+1jzi2jN5nhpjJ6A7YduMOS0jBhnGvV4jg0gAKDB1vqvBsWcQMCOdiqtKpjEcNSBoMHudGwiGdrpofv2PFLWjPCII8DuJtr/JiUkymBNZXWRTDLpZcTeQi6AUtqgE2suw8rZTXrlaZ2Dq6vFqX4/0Q1cXMojXOoei8LyrdSoasxqvv+xUQk3kQ==', 'next-auth.csrf-token': 'd11a7afa594cc323b39542e7ac5640401db13de6c21c3e01d731080556ade6b4%7C1134a842d8d4b64646c07a4d6bbc79003015505c964065990c2527892b364d04', '__Secure-next-auth.callback-url':
           'https%3A%2F%2Fwww.perplexity.ai%2Fapi%2Fauth%2Fsignin-callback%3Fredirect%3DdefaultMobileSignIn', '__cflb': '02DiuDyvFMmK5p9jVbVnMNSKYZhUL9aGmebyqfdFocbvc', '__Secure-next-auth.session-token': 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..740gG5RsUme7L_4f.xhKjBL8UcXAI-MIjOa7qGQN0ypFfiKwDlKz3nbMvIzZktYCZ9OY3TgxnrpLXUbImpN7JNHLasY3Nfjn3WUV7KD72nNTaQNd720alX0PujcN67xj7aN6P5J5KYWR99f_wk36UyS1-TZZ_V53hUcRMnBtvrXSZwSk2otE6Qzba3LDwgpVPq8oImYH1x1ftI9QU72l7c_R9Z82JjQxljhgDuG50Tg.jgO5Efmu0ZSNf4Adxs8A2w', '__cf_bm': 'BRYR.qPJ1CHYLmiP1haljS5DHKg9G2BiiMuRpjbSISU-1713556338-1.0.1.1-U9KND.fH0.TXHObtRlc1XNEag7VSOAcIfWSc8UyLRsZhSYZcSXVUC58YKldVW.CXIlZulV6b97HXVGXBwmxmEA'}

cookies = None
email = None
if __name__ == '__main__':
    perplexity = Perplexity(email=email, cookies=cookies,
                            debug=True)
    answer = perplexity.search_sync("how to take a screenshot?", "copilot")
    print(answer)
#     # perplexity.close()

# session = Session()
# session.headers.update({
#     "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
# })
# r = session.get("https://www.google.com/", impersonate="chrome")
# print(r.request.headers)
# print(session.headers)
# print(r.cookies)

# for k, v in r.headers.items():
#     print(f"{k} => {v}")

# print()
# print(r.text)

# Create an instance of CustomUCWebDriver
# options = uc.ChromeOptions()
# options.add_argument("--headless=new")  # for hidden mode
# driver = CustomUCWebDriver(options=options)

# # Make a POST request and capture the response
# response_data = driver.post("https://example.com", '{"key": "value"}')

# # Print the response data
# print(response_data)
