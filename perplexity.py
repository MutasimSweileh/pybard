import websocket
import websockets.client as websockets
from websockets.client import WebSocketClientProtocol
import asyncio
from utils import as_json, check_if_url, cookies_as_dict, get_http_client, get_useragent
import base64
import json
from typing import Iterable, Dict
from gmail import temp_mail
from os import listdir
from uuid import uuid4
from time import sleep, time
from threading import Thread
from json import loads, dumps
from random import getrandbits
from websocket import WebSocketApp
import undetected_chromedriver as uc
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from ucwebdriver import UC_Webdriver, CustomUCWebDriver
from exceptions import CustomException
import certifi
import ssl
from dotenv import load_dotenv
load_dotenv()


class Perplexity:
    def __init__(self, cookies: str = None, email: str = None, debug=False, use_driver=False, close=True) -> None:
        # self.session: Session = Session()
        self.csrfToken = None
        self.driver = None
        self.loop = None
        self.isLogin = False
        self.email: str = email
        self.use_driver = use_driver
        self.d_cookies = None
        self.copilot = 5
        self.gpt4_limit = 0
        self.upload_limit = 3
        self.mode = None
        self.timeout = 30
        self.socket = None
        self.wss_client: WebSocketClientProtocol | None = None
        self.user_agent: dict = {
            "User-Agent": "Ask/2.4.1/224 (iOS; iPhone; Version 17.1) isiOSOnMac/False", "X-Client-Name": "Perplexity-iOS"}
        self.user_agent = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        }
        self.cookies = self.convert_session(cookies)
        self.row_cookies = self.cookies
        self.debug = debug
        self.session = None
        self.ws = None
        self.last_message = None
        self.n: int = 1
        self.base: int = 420
        self.queue: list = []
        self.recent_conversations: list = []
        self.finished: bool = True
        self.soket_error: str = None
        self.last_uuid: str = None
        self.backend_uuid: str = None  # unused because we can't yet follow-up questions
        self.frontend_session_id: str = str(uuid4())
        self.tmpEmail = temp_mail(email, create=True)
        self._close = close

    def init(self, **kwargs):
        try:
            email = kwargs.get("email", None)
            self.backend_uuid = kwargs.get("conversationId", None)
            self.check_run(email)
            self.soket_error = None
            self.last_message = None
            self.timeout = kwargs.get("use_driver", self.timeout)
            self.use_driver = kwargs.get("use_driver", self.use_driver)
            self.debug = kwargs.get("debug", self.debug)
            self.email = email
            self.mode = kwargs.get("mode", self.mode)
            self.tmpEmail.email = self.email
            self.cookies = self.convert_session(
                kwargs.get("cookies", self.cookies))
            self.session = self.get_session()
            self.get_user_settings(True)
            self.create_account()
            if self.backend_uuid:
                self.getConversation(self.backend_uuid)
        except (Exception, CustomException) as e:
            self.close()
            raise CustomException(e)

    def check_run(self, email=None):
        if not self.finished:
            raise Exception(
                "already searching ...")
        if email != self.email:
            self.session = get_http_client()

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

    def create_account(self, Force=True):
        if self.isLogin and self.email and not self.use_driver:
            # try:
            email = self.tmpEmail.getEmail(None)
            self.email = email
            if not email:
                raise Exception("Email is required")
            url = 'https://www.perplexity.ai/api/auth/signin-email'
            self._debug(url)
            resp = self.session.post(url, data={
                'email':  self.email,
            })
            self._debug(resp.status_code, resp.text)
            if resp.status_code == 200:
                new_msgs = self.tmpEmail.getMessages(
                    "team@mail.perplexity.ai", wait=True)
                if not new_msgs:
                    raise Exception(
                        f'Fail to get email message {email} !')
                new_account_link = new_msgs[0]
                resp = self.session.get(new_account_link)
                self.cookies = resp.cookies.get_dict()
                # self.session.cookies.clear()
                # self.session.cookies.update(resp.cookies.get_dict())
            elif resp.status_code == 429:
                raise Exception({
                    "message": "Too many requests. Try again in 1 minute.",
                    "email": self.email,
                    "cookies": self.get_cookies_dict(),
                })
                raise Exception(
                    f'Too many requests. Try again in 1 minute.')
            else:
                txt = resp.text
                if txt.find("Email is required") != -1 and email and Force:
                    return self.create_account(False)
                raise Exception(
                    f'Error triggering email {email} sign in & {txt}')
            # except Exception as e:
            #     raise Exception(str(e))
        self.t: str = self._get_t()
        self.sid: str = self._get_sid()
        self._ask_anonymous_user()
        if self.isLogin:
            self.get_user_settings()
        # self.ws: WebSocketApp = self._init_websocket()
        # self.ws_thread: Thread = Thread(target=self.ws.run_forever).start()
        # while self.ws and hasattr(self.ws, "sock") and not (self.ws.sock and self.ws.sock.connected):
        #     if self.soket_error:
        #         break
        #     sleep(0.01)
        return True

    def get_session(self):
        # self.session = Session(impersonate="chrome124")
        self.session = get_http_client()
        # self.session.headers.update({
        #     "User-Agent": get_useragent(),
        #     # "X-Client-Name": "Perplexity-iOS",
        # })
        # self.session.headers.update(self.user_agent)
        try:
            if self.cookies:
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
                self.isLogin = True
                self.cookies = None
            else:
                self.isLogin = False
                self._init_session_without_login()
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

    def get_headers_dict(self):
        headers = {}
        for k, v in self.session.headers.items():
            k = map(lambda x: x.title(), k.split("-"))
            k = "-".join(k)
            headers[k] = v
        return headers

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
            self._debug(url)
            re = self.session.get(
                url=url)
            self._debug(re.status_code, re.text)
        else:
            self.get_driver(url)
            self.session.cookies.update(self.driver_cookies())
            user_agent = self.driver.user_agent()
            self.user_agent = {
                "User-Agent": user_agent}
            # print(self.user_agent)
            # self.session.headers.update(self.user_agent)

    def _debug(self, *st):
        if self.debug:
            print(st)
            print("="*20)

    def _auth_session(self) -> None:
        if not self.cookies:
            return False
        url = "https://www.perplexity.ai/api/auth/session"
        self._debug(url)
        re = self.session.get(
            url=url)
        self._debug(re.status_code, re.text)
        if re.status_code == 200:
            return re.json()
        return False

    def check_limit(self):
        if self.gpt4_limit <= 0 and self.mode == "copilot":
            raise Exception({
                "message": "Exceeded completions",
                "email": self.email,
                "cookies": self.get_cookies_dict(),
            })
            raise Exception("Exceeded completions")

    def get_user_settings(self, check=False):
        if not self.cookies:
            return False
        url = "https://www.perplexity.ai/p/api/v1/user/settings"
        self._debug(url)
        re = self.session.get(
            url=url)
        self._debug(re.status_code, re.text)
        if re.status_code == 200:
            j = re.json()
            self.copilot = j["query_count_copilot"]
            self.copilot = j["gpt4_limit"]
            self.gpt4_limit = j["gpt4_limit"]
            self.upload_limit = j["upload_limit"]
            if check and self.gpt4_limit <= 0 and self.mode == "copilot":
                raise Exception({
                    "message": "Exceeded completions",
                    "email": self.email,
                    "cookies": self.get_cookies_dict(),
                })
            return j
        return False

    def _get_t(self) -> str:
        return format(getrandbits(32), "08x")

    def _get_sid(self) -> str:
        url = f"https://www.perplexity.ai/socket.io/?EIO=4&transport=polling&t={self.t}"
        if self.use_driver:
            j = self.get_driver(url)
        else:
            self._debug(url)
            re = self.session.get(
                url=url
            )
            j = re.text
            self._debug(re.status_code, re.text)
            if re.status_code != 200:
                raise Exception(
                    f"invalid session status_code: {re.status_code}")
        # return loads(j[1:])["sid"]
        socket = json.loads(j[1:])
        sid = socket["sid"]
        self.socket = {
            "ping_interval": socket["pingInterval"],
            "ping_timeout": socket["pingTimeout"],
        }
        return sid

    def _ask_anonymous_user(self) -> bool:
        url = f"https://www.perplexity.ai/socket.io/?EIO=4&transport=polling&t={self.t}&sid={self.sid}"
        if self.use_driver:
            response = self.driver.post(
                url, "40{\"jwt\":\"anonymous-ask-user\"}")
            cookies = self.driver_cookies()
            self.session.cookies.update(cookies)
            self.close_driver()
        else:
            self._debug(url)
            response = self.session.post(
                url=url,
                data="40{\"jwt\":\"anonymous-ask-user\"}"
            )
            self._debug(response.status_code, response.text)
            headers = {}
            for k, v in response.headers.items():
                headers[k] = v
            # print(headers)
            # print(response.cookies.get_dict())
            # self.session.headers.update(headers)
            # self.session.cookies = response.cookies
            response = response.text
        if response != "OK":
            raise Exception(
                "invalid session")
        return True

    def _start_interaction(self) -> None:
        self.finished = False
        self.last_message = None
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
            ws.send("2probe".encode("utf-8"))
            ws.send("5".encode("utf-8"))

        def on_message(ws: WebSocketApp, message: str) -> None:
            message = str(message)
            # print(message)
            self.last_message = message
            if message == "2":
                ws.send("3".encode("utf-8"))
            elif message == '3probe':
                ws.send('5'.encode("utf-8"))
            elif not self.finished:
                self.get_socket_message(message)

        def on_error(ws: WebSocketApp, message: str):
            message = str(message)
            m = f"websocket error: {message}"
            if self.debug:
                print(m)
            self.soket_error = {
                "message": m,
                "cookies": self.get_cookies_dict()
            }
            if self.last_message:
                self.soket_error["message"] += " & "+str(self.last_message)
        header = {}
        # header["Accept-Encoding"] = "gzip, deflate, br, zstd"
        # header["Connection"] = "Upgrade"
        # header["Cookie"] = self._get_cookies_str()
        # header["Host"] = "www.perplexity.ai"
        # header["Origin"] = "https://www.perplexity.ai"
        # header["Pragma"] = "no-cache"
        # header["Upgrade"] = "websocket"
        # header["User-Agent"] = self.get_headers_dict()["User-Agent"]
        # print(header)
        # headers = self.get_headers_dict()
        # print(headers)
        # websocket.enableTrace(True)
        # return self.session.ws_connect(
        #     url=f"wss://www.perplexity.ai/socket.io/?EIO=4&transport=websocket&sid={self.sid}",
        #     # header={"User-Agent": self.get_headers_dict()["User-Agent"]},
        #     # header=self.get_headers_dict(),
        #     # cookie=self._get_cookies_str(),
        #     on_open=on_open,
        #     on_message=on_message,
        #     on_error=on_error)
        return websocket.WebSocketApp(
            url=f"wss://www.perplexity.ai/socket.io/?EIO=4&transport=websocket&sid={self.sid}",
            header={"User-Agent": self.get_headers_dict()["User-Agent"]},
            # header=self.get_headers_dict(),
            cookie=self._get_cookies_str(),
            on_open=on_open,
            on_message=on_message,
            on_error=on_error
        )

    def prompt_input(self, _last_answer, solvers={}):
        query = _last_answer["query_str"]
        self.backend_uuid = _last_answer['backend_uuid']
        focus = _last_answer['search_focus']
        if type(_last_answer['text']) is str:
            _last_answer['text'] = loads(_last_answer['text'])
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

    def get_socket_message(self, message: str):
        if message.startswith("42"):
            message: list = loads(message[2:])
            content: dict = message[1]
            if ("status" in content and content["status"] == "pending"):
                self.timeout *= 2
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
            if "status" in message and message["status"] == "failed":
                self.soket_error = message["text"]
            elif "step_type" in message and message["step_type"] == "PROMPT_INPUT":
                self.prompt_input(message)
            elif ("uuid" in message and message["uuid"] != self.last_uuid) or "uuid" not in message:
                self.queue.append(message)
                self.finished = True

    async def _ask6(self, query: str, mode: str = "concise", focus: str = "internet", attachments: list[str] = [], language: str = "en-US", in_page: str = None, in_domain: str = None):
        try:
            # header = self.user_agent
            header = {}
            header["User-Agent"] = self.get_headers_dict()["User-Agent"]
            header["Cookie"] = self._get_cookies_str()
            # print(header)
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
            ssl_context.load_verify_locations(certifi.where())
            self.ws = await websockets.connect(
                f"wss://www.perplexity.ai/socket.io/?EIO=4&transport=websocket&sid={self.sid}",
                extra_headers=header, max_size=None, ssl=ssl_context
            )
        except Exception as e:
            raise Exception({
                "message": str(e),
                "email": self.email,
                "cookies": self.get_cookies_dict(),
            })
            raise CustomException(
                "Failed to connect to Copilot, connection timed out") from None
        await self.ws.send("2probe")
        await self.ws.recv()
        await self.ws.send("5")
        await self.ws.recv()
        self._start_interaction()
        ws_message: str = f"{self.base + self.n}" + dumps([
            "perplexity_ask",
            query,
            {
                "version": "2.9",
                "source": "default",  # "ios"
                "frontend_session_id": self.frontend_session_id,
                "language": language,
                # "timezone": "CET",
                'last_backend_uuid': self.backend_uuid,
                "attachments": attachments,
                "search_focus": focus,
                "frontend_uuid": str(uuid4()),
                "mode": mode,
                "prompt_source": "user",
                "query_source": "home",
                "is_incognito": False,
                # "use_inhouse_model": True
                "in_page": in_page,
                "in_domain": in_domain
            }
        ])

        await self.ws.send(ws_message)
        while not self.finished:
            message = str(await self.ws.recv())
            self.get_socket_message(message)
        await self.ws.close()

    def _ask(self, query: str, mode: str = "concise", focus: str = "internet", attachments: list[str] = [], language: str = "en-US", in_page: str = None, in_domain: str = None):
        try:
            self.ws = self.session.wss_connect(
                f"wss://www.perplexity.ai/socket.io/?EIO=4&transport=websocket&sid={self.sid}",
                **self.socket,
                origin="https://www.perplexity.ai"
            )
        except Exception as e:
            raise Exception({
                "message": str(e),
                "email": self.email,
                "cookies": self.get_cookies_dict(),
            })
        self.session.wss_send("2probe")
        self.session.wss_send("5")
        self._start_interaction()
        ws_message: str = f"{self.base + self.n}" + dumps([
            "perplexity_ask",
            query,
            {
                "version": "2.9",
                "source": "default",  # "ios"
                "frontend_session_id": self.frontend_session_id,
                "language": language,
                # "timezone": "CET",
                'last_backend_uuid': self.backend_uuid,
                "attachments": attachments,
                "search_focus": focus,
                "frontend_uuid": str(uuid4()),
                "mode": mode,
                "prompt_source": "user",
                "query_source": "home",
                "is_incognito": False,
                # "use_inhouse_model": True
                "in_page": in_page,
                "in_domain": in_domain
            }
        ])

        self.session.wss_send(ws_message)
        while not self.finished:
            message = self.session.wss_recv()
            self.get_socket_message(message)

        self.session.close()

    def _s(self, query: str, mode: str = "concise", focus: str = "internet", attachments: list[str] = [], language: str = "en-GB", in_page: str = None, in_domain: str = None) -> None:

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
        self.mode = mode
        # if ai_model not in ['default', 'experimental', 'gpt-4', 'claude-2.1',
        #                     'gemini pro']:
        #     raise Exception(
        #         'Ai models --> ["default", "experimental", "gpt-4", "claude-2.1", "gemini pro"]')
        if in_page:
            focus = "in_page"
        if in_domain:
            focus = "in_domain"
        if self.soket_error:
            raise Exception(self.soket_error)
        self._start_interaction()
        ws_message: str = f"{self.base + self.n}" + dumps([
            "perplexity_ask",
            query,
            {
                "version": "2.9",
                "source": "default",  # "ios"
                "frontend_session_id": self.frontend_session_id,
                "language": language,
                # "timezone": "CET",
                'last_backend_uuid': self.backend_uuid,
                "attachments": attachments,
                "search_focus": focus,
                "frontend_uuid": str(uuid4()),
                "mode": mode,
                "prompt_source": "user",
                "query_source": "home",
                "is_incognito": False,
                # "use_inhouse_model": True
                "in_page": in_page,
                "in_domain": in_domain
            }
        ])
        print(ws_message)
        self.ws.send(ws_message.encode("utf-8"))

    def search(self, query: str, mode: str = "concise", focus: str = "internet", attachments: list[str] = [], language: str = "en-GB", timeout: float = 30, in_page: str = None, in_domain: str = None) -> Iterable[Dict]:
        try:
            self.mode = mode
            self._s(query, mode, focus, attachments,
                    language, in_page, in_domain)
            start_time: float = time()
            while (not self.finished) or len(self.queue) != 0:
                if timeout and time() - start_time > timeout:
                    self.finished = True
                    raise Exception("timeout")
                if len(self.queue) != 0:
                    break
                    # yield self.queue.pop(0)
            return self.queue.pop(-1)
        except Exception as e:
            raise CustomException(str(e))
        finally:
            self.close()

    def run_task(self, fn):
        if not self.loop:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
        task = self.loop.create_task(fn())
        self.loop.run_until_complete(task)
        result = task.result()
        return result

    def search_sync(self, query: str, mode: str = "concise", focus: str = "internet", attachments: list[str] = [], language: str = "en-US", timeout: float = 30, in_page: str = None, in_domain: str = None) -> dict:
        try:
            self.mode = mode
            self.timeout = timeout
            self.check_limit()
            self._ask(query, mode, focus, attachments,
                      language, in_page, in_domain)
            re = self.queue.pop(-1)
            try:
                re['text'] = json.loads(re['text'])
                if "answer" not in re['text']:
                    answer = json.loads(re["text"][-1]["content"]["answer"])
                    re['text'] = answer
                del re["text"]["chunks"]
                re["login"] = self.isLogin
                re["cookies"] = self.get_cookies_dict()
                re["email"] = self.email
                re["query_count_copilot"] = self.copilot
                self.backend_uuid = re["backend_uuid"]
            except Exception as es:
                raise Exception({
                    "message": str(es),
                    "last_json": re,
                    "last_message": self.last_message
                })
            return re
        except (Exception, CustomException) as e:
            raise CustomException(e)
        finally:
            if self._close:
                self.close()

    def search_sync2(self, query: str, mode: str = "concise", focus: str = "internet", attachments: list[str] = [], language: str = "en-GB", timeout: float = 30, in_page: str = None, in_domain: str = None) -> dict:
        try:
            self.mode = mode
            self.timeout = timeout
            self.check_limit()
            self._s(query, mode, focus, attachments,
                    language, in_page, in_domain)
            start_time: float = time()
            print(self.finished)
            while not self.finished:
                if self.soket_error:
                    raise Exception(self.soket_error)
                if self.timeout and time() - start_time > self.timeout:
                    raise Exception(
                        f"timeout & last message: {self.last_message}")
            print(self.finished)
            re = self.queue.pop(-1)
            try:
                re['text'] = json.loads(re['text'])
                if "answer" not in re['text']:
                    answer = json.loads(re["text"][-1]["content"]["answer"])
                    re['text'] = answer
                del re["text"]["chunks"]
                re["login"] = self.isLogin
                re["cookies"] = self.get_cookies_dict()
                re["email"] = self.email
                re["query_count_copilot"] = self.copilot
                self.backend_uuid = re["backend_uuid"]
            except Exception as es:
                raise Exception({
                    "message": str(es),
                    "last_json": re,
                    "last_message": self.last_message
                })
            return re
        except Exception as e:
            print(e)
            raise CustomException(e)
        finally:
            if self._close:
                self.close()

    def upload(self, filename: str) -> str:
        assert self.finished, "already searching"
        assert filename.split(".")[-1] in ["txt", "pdf"], "invalid file format"

        if filename.startswith("http"):
            file = self.session.get(filename).content
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

        self.session.post(
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

    def getConversation(self, id):
        self.threads()
        conversation = filter(
            lambda x: x["uuid"] == id, self.recent_conversations)
        conversation = list(conversation)
        if len(conversation) > 0:
            return conversation[0]
        raise CustomException("Conversation not found")

    def threads(self, query: str = None, limit: int = None) -> list[dict]:
        try:
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
                    self.recent_conversations = self.queue.pop(0)
                    break
            return self.recent_conversations
        except Exception as e:
            raise CustomException(e)

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
        self.finished = True
        if self.ws and hasattr(self.ws, 'sock') and self.ws.sock.connected:
            self.ws.close()
            self.ws = None
        if self.session:
            self.session.close()
            self.session = None
        if self.loop:
            self.loop.close()
            self.loop = None
        self.finished = True
        self.last_message = None
        self.close_driver()


email = "wu.matarice@everysimply.com"
email = "lobeyi.moda@theglossylocks.com"
conversationId = "9f4fa3dd-06d9-4bf7-86b0-e8888529c2d35"
conversationId = None
cookies = "eyJBV1NBTEIiOiJDR0VRMUlaNnJ4K3lZUlwveG5QeE5RN25tUE83VFlMbllSY0xWVWRBN0tZMkFGVllDUjd3ZG1WZHNFclFUNVk0VkV1YSt0SiszdUd5MUhPWlgrOFNzQTlnMW9GdVBRNFNTMThoRFFYeHNqUGhaa3l2UFdPSzVuMWZKTk5hM01ydkxXZHhnN0ZuOGxCc01SV2tqOFpVZElKUGl0Z1laNmFVNUZuM2JPclwvaVEwbW9LZGZPb3BLNTE3cVd2NWhubkE9PSIsIkFXU0FMQkNPUlMiOiJDR0VRMUlaNnJ4K3lZUlwveG5QeE5RN25tUE83VFlMbllSY0xWVWRBN0tZMkFGVllDUjd3ZG1WZHNFclFUNVk0VkV1YSt0SiszdUd5MUhPWlgrOFNzQTlnMW9GdVBRNFNTMThoRFFYeHNqUGhaa3l2UFdPSzVuMWZKTk5hM01ydkxXZHhnN0ZuOGxCc01SV2tqOFpVZElKUGl0Z1laNmFVNUZuM2JPclwvaVEwbW9LZGZPb3BLNTE3cVd2NWhubkE9PSJ9"
cookies = {
    "AWSALB": "7N7zAJUi2ByjukOEEzAxeua6dqxJN2a4J435Yc194pVkco/ipiNd4jfT9BR3pr8vdE0KqdguUN7ZDaejbj67UCD9JVmnvkAvUq8uuxwm98VfMwQqc1KCMWasaBcZvEFK2Za67974yPNFpT8ysXa1+rOWWi3I7lcylxcJ0dWEDGJ3bTpUYtddLYd91dpS1w==",
    "AWSALBCORS": "7N7zAJUi2ByjukOEEzAxeua6dqxJN2a4J435Yc194pVkco/ipiNd4jfT9BR3pr8vdE0KqdguUN7ZDaejbj67UCD9JVmnvkAvUq8uuxwm98VfMwQqc1KCMWasaBcZvEFK2Za67974yPNFpT8ysXa1+rOWWi3I7lcylxcJ0dWEDGJ3bTpUYtddLYd91dpS1w==",
    "__Secure-next-auth.session-token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..h5weT02qIvTc8Hqf.JEfLCw6wc6P3WXKH88CCrVm2pI0o--z9zwUcH9EQS9ZY25zhXNm0Mqq5JMDeKjFCS4IYg7rkdvvDPpQSECZwKbdN37LFk8f_6BkXcbWU2R8DNzErJpu5nQLr3X_5KVZGcyPG3JYhl3kSAEMXS1Ffl3jyo60Urpt3lINKwNAXG-wdYyG3H-YrYUkC5w_As9KAlXRo2DUbHmwGGfMy-vLqLQiWpA._CRYqzEur6yMQujTOv6Kkw",
    "__cf_bm": "P33UInOSP1bTpEVvje93wui52b9kWJvLmGkFe3gegeY-1716864035-1.0.1.1-qcQ591ioIBgP4bMqS4pOlAs.xhF6iOj8J0CL.6Jaw53eQXnMVnwFN4HOLEUoZ4_BYKIg1b2PX1KhYzAcN4YFrg",
    "__cflb": "02DiuDyvFMmK5p9jVbVnMNSKYZhUL9aGkRuNmGVCyh1uW",
    "next-auth.callback-url": "https%3A%2F%2Fwww.perplexity.ai%2Fapi%2Fauth%2Fsignin-callback%3Fredirect%3DdefaultMobileSignIn",
    "next-auth.csrf-token": "ee1c20d0586b6d784f222b4076650039d468dec7f717ca54d608933a79e2beae%7C7d78595ba336e0a52ed3b1513993257be8ba627151b09fb2090ee2e7229d69d0",
    "pplx.visitor-id": "e9a15c14-b2d4-480e-b523-e687d04996a7"
}
# cookies = "eyJBV1NBTEIiOiJXTDVHYlBHcGRNUHo4RTRXXC8zaW5QWDc3bmJmYk16cVcxbmJ3dXNhdkFWREtRdFVqN1lBT2VENEhxMjc5VFVoaTd2NEJadFFYcE5cL0lNaENMZXRua3YyUmNIaU93Q2tGR2I1TjNKNFZ3WTlhVm56MldqQWRxYVlYY1IyamFsQzlKNlV3ZnBLXC9jRzlIRGxVb3h6OW5PRXd0aUlMenZpd2piVGJxVEZCcDNydStRcE1tZUVFb3QyY2Iyenhvcmx3PT0iLCJBV1NBTEJDT1JTIjoiV0w1R2JQR3BkTVB6OEU0V1wvM2luUFg3N25iZmJNenFXMW5id3VzYXZBVkRLUXRVajdZQU9lRDRIcTI3OVRVaGk3djRCWnRRWHBOXC9JTWhDTGV0bmt2MlJjSGlPd0NrRkdiNU4zSjRWd1k5YVZuejJXakFkcWFZWGNSMmphbEM5SjZVd2ZwS1wvY0c5SERsVW94ejluT0V3dGlJTHp2aXdqYlRicVRGQnAzcnUrUXBNbWVFRW90MmNiMnp4b3Jsdz09IiwiX19TZWN1cmUtbmV4dC1hdXRoLmNhbGxiYWNrLXVybCI6Imh0dHBzJTNBJTJGJTJGd3d3LnBlcnBsZXhpdHkuYWkiLCJfX1NlY3VyZS1uZXh0LWF1dGguc2Vzc2lvbi10b2tlbiI6ImV5SmhiR2NpT2lKa2FYSWlMQ0psYm1NaU9pSkJNalUyUjBOTkluMC4uZVlGYkdKdWRsaXdCOHRZYS5mMi1vbEpwQmNFTWNwU3YzRHlFcFA3ZFc5dTUxaE1jU0pJYnVIWjMybUxabXp5MkVPM2VBT3BVZ1RUa3BqWndlaTFjbzIwUWczdzlWMF9uQmxYeU9VLVZDQ3VDMUpkSHZuMFBhYzB6SXp1WGpmTGVFRFBMR05LbjdUS0dBVDlCRm1KdkRFa3YxRzlJWDVXOUNISHp0b2ttT1plQnZMLUE2T3BGSndEb0NiM2l2UHNHdUZLVGZiMXpoV1lUQlpYWGVhWTU3dWV0czZVZDF5a0JJalYycUNYSTQ4Uy1wZ1RHTHhnLklFM3oyVmh6M0RSNU1jMVZXTTRDTlEiLCJfX2NmX2JtIjoidVNJaXc2NEdjUWVsRmx2aG80RmRwa01QRTFRQXdmSHYzV05DZ3BWY1RWMC0xNzExODQ2MTM2LTEuMC4xLjEtNWhfbldIMXViTTFsc01mdTJ2M2FqMEl4Q09YT3ltNGRpWDZYdDRGcTFYQzZvRE9JRURqdlc5R0hNeG1IaURVcWFNbHUwdzRhZy5mMGtuTXNFNmJyNVEiLCJfX2NmbGIiOiIwMkRpdUR5dkZNbUs1cDlqVmJWbk1OU0tZWmhVTDlhR21qRzhFWWY0NzhDengiLCJuZXh0LWF1dGguY3NyZi10b2tlbiI6ImE2MTE2ZGMxMGM5OWQ1ODAzNmNjMDNiMTA0YjdiMjE3MmM2NTQ3ZWY1NGVlMDM0MmFiNTExOWQ1ZGY0M2I2MTYlN0M5OTQ3ZDZjYjYwNDI3MmI3ZDJmYTQyNGQ3YzBkZjVkZDMxMTM3ZmQ1NTlmMWU0YWNjZTMyNmVlZDk3MjQ3YzlhIn0="
if __name__ == '__main__':
    perplexity = Perplexity()
    # answer = perplexity.get_driver("https://www.perplexity.ai/")
    # answer = perplexity.driver_cookies()
    # perplexity.close_driver()
    answer = perplexity.init(debug=True, email=email, cookies=cookies)
    # answer = perplexity.init(email=email, cookies=cookies,
    #                          debug=True, conversationId=conversationId)
    # asyncio.run(perplexity._ask("how are you?"))
    # answer = perplexity.getConversation(conversationId)
    # answer = perplexity.threads()
    # c = perplexity.get_cookies_dict()
    # perplexity.close()
    try:
        # raise CustomException({
        #     "message": "Exceeded completions",
        #     "email": perplexity.email,
        #     "cookies": perplexity.get_cookies_dict(),
        # })
        answer = perplexity.search_sync(
            "do dogs get tired of barking")
        print(answer)
    except CustomException as e:
        print(e.getJSON())
