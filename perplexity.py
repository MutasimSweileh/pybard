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
from requests import Session, get, post
import cloudscraper

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


class Perplexity:
    def __init__(self, cookies: str = None, email: str = None, debug=False) -> None:
        self.session: Session = Session()
        self.csrfToken = None
        self.isLogin = False
        self.email: str = email
        self.user_agent: dict = {
            "User-Agent": "Ask/2.4.1/224 (iOS; iPhone; Version 17.1) isiOSOnMac/false", "X-Client-Name": "Perplexity-iOS"}
        self.session.headers.update(self.user_agent)
        self.cookies = self.convert_session(cookies)
        self.row_cookies = self.cookies
        self.session = self.get_session()
        self.ws = None
        self.last_message = None
        self.debug = debug

        self.n: int = 1
        self.base: int = 420
        self.queue: list = []
        self.finished: bool = True
        self.last_uuid: str = None
        self.backend_uuid: str = None  # unused because we can't yet follow-up questions
        self.frontend_session_id: str = str(uuid4())
        self.tmpEmail = temp_mail(email, create=True)

    def create_account(self):
        if not self.isLogin and self.email:
            self.copilot = 5
            self.file_upload = 3
            try:
                email = self.tmpEmail.getEmail(None)
                self.email = email
                resp = self.session.post('https://www.perplexity.ai/api/auth/signin-email', data={
                    'email': email,
                })
                if resp.status_code == 200:
                    new_msgs = self.tmpEmail.getMessages(
                        "team@mail.perplexity.ai", wait=True)
                    if not new_msgs:
                        raise Exception(
                            f'Fail to get email message {self.email} !')
                    new_account_link = new_msgs[0]
                    self.session.get(new_account_link)
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
        self.session = cloudscraper.create_scraper(
            debug=self.debug,
            delay=20,
            browser={
                'browser': 'chrome',
                'platform': 'ios',
                'desktop': False
            },
            interpreter='js2py',
            allow_brotli=False,
            captcha={
                'provider': '2captcha',
                'api_key': os.getenv("TwoCaptcha_API_KEY")
            }
        )
        self.user_agent["User-Agent"] = self.session.headers.get("User-Agent")
        # self.session.headers.update(self.user_agent)
        try:
            if self.cookies:
                self.csrfToken = self.cookies.get(
                    "next-auth.csrf-token", self.csrfToken)
                del self.cookies["__Secure-next-auth.callback-url"]
                self.session.cookies.update(self.cookies)

            if not self._auth_session():
                self.isLogin = False
                self._init_session_without_login()
            else:
                self.isLogin = True
            cookies = self.session.cookies.get_dict()
            self.csrfToken = cookies.get(
                "next-auth.csrf-token", self.csrfToken)
            if self.csrfToken:
                self.csrfToken = self.csrfToken.split('%')[0]
            return self.session
        except Exception as e:
            m = str(e)
            print("get_session:", m)
            raise CustomException(m)

    def convert_session(self, cookies):
        try:
            cookies = base64.b64decode(cookies).decode("utf-8")
        except:
            pass
        try:
            if cookies and type(cookies) is not dict:
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
        self.session.get(
            url=f"https://www.perplexity.ai/search/{str(uuid4())}")
        self.session.headers.update(self.user_agent)

    def _auth_session(self) -> None:
        re = self.session.get(url="https://www.perplexity.ai/api/auth/session")
        if re.status_code == 200:
            return re.json()
        return False

    def _get_t(self) -> str:
        return format(getrandbits(32), "08x")

    def _get_sid(self) -> str:
        re = self.session.get(
            url=f"https://www.perplexity.ai/socket.io/?EIO=4&transport=polling&t={self.t}"
        )
        if re.status_code != 200:
            raise Exception(
                "invalid session")
        return loads(re.text[1:])["sid"]

    def _ask_anonymous_user(self) -> bool:
        response = self.session.post(
            url=f"https://www.perplexity.ai/socket.io/?EIO=4&transport=polling&t={self.t}&sid={self.sid}",
            data="40{\"jwt\":\"anonymous-ask-user\"}"
        ).text
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
        for key, value in self.session.cookies.get_dict().items():
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
                re["cookies"] = self.session.cookies.get_dict()
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

        # if self.email:
        #     with open(".perplexity_session", "r") as f:
        #         perplexity_session: dict = loads(f.read())

        #     perplexity_session[self.email] = self.session.cookies.get_dict()

        #     with open(".perplexity_session", "w") as f:
        #         f.write(dumps(perplexity_session))


# email = "pefecu.jiyujori@theglossylocks.com"
# email = "wu.matarice@everysimply.com"
# cookies = "eyJBV1NBTEIiOiJcL3BYbWNMRWN6TmQ1cHhsQjI5NTdTT3M0REUzNUJYd2FKTVwvSSs4RCttbHF1WlJZd3dtR1JLandrT2N3TXYzNmxENldvVkxOa3pxc0x0THJWSUo1bFg4N2IzZCszSkM4XC9UYVdHcUNadWdSeU84UFhDTXZUT1JDWFVLck90RTZKTkxLZ2tzQkVSMkhmWllab3hwWWNzSEVoWXREam80MlJlTWltQ2xsMTZKdm1VZTN6SHFtcVwvWENEek5VcWlIdz09IiwiQVdTQUxCQ09SUyI6IlwvcFhtY0xFY3pOZDVweGxCMjk1N1NPczRERTM1Qlh3YUpNXC9JKzhEK21scXVaUll3d21HUktqd2tPY3dNdjM2bEQ2V29WTE5renFzTHRMclZJSjVsWDg3YjNkKzNKQzhcL1RhV0dxQ1p1Z1J5TzhQWENNdlRPUkNYVUtyT3RFNkpOTEtna3NCRVIySGZaWVpveHBZY3NIRWhZdERqbzQyUmVNaW1DbGwxNkp2bVVlM3pIcW1xXC9YQ0R6TlVxaUh3PT0iLCJfX1NlY3VyZS1uZXh0LWF1dGguY2FsbGJhY2stdXJsIjoiaHR0cHMlM0ElMkYlMkZ3d3cucGVycGxleGl0eS5haSUyRmFwaSUyRmF1dGglMkZzaWduaW4tY2FsbGJhY2slM0ZyZWRpcmVjdCUzRGRlZmF1bHRNb2JpbGVTaWduSW4iLCJfX1NlY3VyZS1uZXh0LWF1dGguc2Vzc2lvbi10b2tlbiI6ImV5SmhiR2NpT2lKa2FYSWlMQ0psYm1NaU9pSkJNalUyUjBOTkluMC4uX1IxZ09yTEJRZjFEcHlUMS45MzR3NzRzYlg5WkxxM1N2aDRXbzRmQ3V4RVJxTjgxMFlJdHFMdUxOblhmSnA1NjdvNGZYZ0I1TDhPUUdIbVdXS0hlY3I3ZFJfbU1wVFhJQV9FcFd2X3dkSXJOb0ZoeXZod1I0VEFSQTFJV1ZKRmhrdUlEbmduNWthV0l0ZC1hY0pVV25HMWZ6dHlDVHJNeHNYRUw4dXRvcG92dUxuVjRKQXREV29Yc29TRllfT2lWVDlhUlhqUW5oQlFhM2I0NERhdEpIVS1RVFVDdFlQMkxzNnRrVGFMRFEzUS5Udi0zeG56M3pTNklyWlVaOHVNdkN3IiwiX19jZl9ibSI6Ijh3WWRkZkRQVnhPUWIuQzBDVTFSQkxYemdYMVJkNDFCcmRnNUtEVEM2Tm8tMTcxMzQ0ODE1MC0xLjAuMS4xLUVRc0FwNTNzZVYwZklxbmJ6RGFxRjdUZlVwLlYwR1NYQ2pNWUpLbTJwcnpVRFJzNzVWN194bHo3NUNYYVZHel85Ql9HXzg1RzNZUzgwRlZZYmRrYlZnIiwiX19jZmxiIjoiMDJEaXVEeXZGTW1LNXA5alZiVm5NTlNLWVpoVUw5YUdtSjVabTFEQWhSY244IiwibmV4dC1hdXRoLmNzcmYtdG9rZW4iOiI2ZDU4ZWM0ZjIzZDMyMmZkODIyOTIyNGUzZGU0NmRmNzc1NzI5NWJiM2VmNTVjOTVlYmU5NDExODFjOGQzNjQyJTdDZjhjOTYyMWY1NmYwNjRjZjFmYTE4ZDNlZDA2Yjg2ZWY5MzBhM2ViNWJiMzhmNThlNGNkZWQ2YTM0Mzg1MjExMiJ9"
# # cookies = None
# # email = None
# perplexity = Perplexity(email=email, cookies=cookies)
# answer = perplexity.search_sync("how to take a screenshot?", "copilot")
# print(answer)
# for a in answer:
#     #     print(a)
# perplexity.close()
