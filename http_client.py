
import ssl
from typing import OrderedDict
import certifi
import tls_client
from tls_client import structures, settings
import asyncio
import json
import random
from curl_cffi.requests import Session, WebSocket, Response, Cookies, BrowserType
import websockets


class CustomHeaders(structures.CaseInsensitiveDict):
    def get_dict(self):
        return {k: v for k, v in self.items()}


class CustomCookies(Cookies):
    def get_dict(self):
        return {k: v for k, v in self.items()}


class HttpClient(Session):

    def __init__(self, *args, **kwargs) -> None:
        self.brower = "chrome_120"
        self.timeout = 30
        self.debug = False
        self.loop = None
        self.ws: websockets.WebSocketClientProtocol = None
        brower = kwargs.get("brower", self.brower)
        headers = kwargs.get("headers", {})
        self.is_curl = issubclass(self.__class__, Session)
        self.timeout = self.timeout_seconds = kwargs.get(
            "timeout", self.timeout)
        kwargs = self.remove_unwanted(kwargs)
        kwargs = {
            "client_identifier": brower,
            "debug": self.debug,
            "random_tls_extension_order": True,
            **kwargs
        }
        client_identifier = kwargs["client_identifier"]
        if (self.is_curl):
            if not BrowserType.has(client_identifier):
                client_identifier = "chrome"
            kwargs["impersonate"] = client_identifier
            del kwargs["client_identifier"]
            del kwargs["random_tls_extension_order"]
        elif client_identifier not in settings.ClientIdentifiers.__args__:
            kwargs["client_identifier"] = "chrome_120"
        super().__init__(**kwargs)
        headers = {
            **self.get_browser_headers(rand=True),
            **headers
        }
        print(kwargs)
        self.headers.update(headers)
        self.headers = CustomHeaders(self.headers)
        if (self.is_curl):
            self.cookies = CustomCookies(self.cookies)

    def remove_unwanted(self, headers: dict = {}, df=None):
        if not df:
            df = ["client_identifier", "ja3_string", "h2_settings", "h2_settings_order", "supported_signature_algorithms", "supported_delegated_credentials_algorithms", "supported_versions", "key_share_curves", "cert_compression_algo",
                  "additional_decode", "pseudo_header_order", "connection_flow", "priority_frames", "header_order", "header_priority", "random_tls_extension_order", "force_http1", "catch_panics", "debug", "certificate_pinning"]
        new_headers = {}
        for k, v in headers.items():
            if k in df:
                new_headers[k] = v
        return new_headers

    def get_user_agents(self, num_results=100, rand=False):
        agents = self.get_json("agents")
        if not agents:
            agents = self.get(
                url='https://headers.scrapeops.io/v1/user-agents',
                params={
                    'api_key': 'daa95dde-0cce-438f-a0fb-ae85c994e4d9',
                    'num_results': num_results}
            ).json()["result"]
            self.get_json("agents", agents)

        return agents if not rand else random.choice(agents)

    def get_browser_headers(self, num_results=100, rand=False):
        headers = self.get_json("headers")
        if not headers:
            headers = self.get(
                url='https://headers.scrapeops.io/v1/browser-headers',
                params={
                    'api_key': 'daa95dde-0cce-438f-a0fb-ae85c994e4d9',
                    'num_results': num_results}
            ).json()["result"]
            self.get_json("headers", headers)
        return headers if not rand else random.choice(headers)

    def run_task(self, fn):
        if not self.loop:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
        task = self.loop.create_task(fn())
        self.loop.run_until_complete(task)
        result = task.result()
        return result

    def request(self, *args, **kwargs):
        if self.is_curl:
            return super().request(**kwargs)
        return self.execute_request(**kwargs)

    def close(self) -> str:
        self.ws_close()
        if self.loop:
            self.loop.close()
            self.loop = None
        return super().close()

    def ws_close(self):
        async def _():
            await self.ws.close()
            self.ws = None
        if self.ws:
            self.run_task(_)

    def _get_cookies_str(self) -> str:
        cookies = ""
        for key, value in self.cookies.get_dict().items():
            cookies += f"{key}={value}; "
        return cookies[:-2]

    def wss_send(self, message: str):
        async def _():
            await self.ws.send(message)
            return str(await self.ws.recv())
        return self.run_task(_)

    def wss_recv(self):
        async def _():
            try:
                return str(await self.ws.recv())
            except:
                pass
        return self.run_task(_)

    def wss_connect(self, url, *args, **kwargs):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        ssl_context.load_verify_locations(certifi.where())
        kwargs = {
            "user_agent_header": self.headers.get("User-Agent"),
            "ssl": ssl_context,
            "max_size": None,
            # "origin": "https://www.perplexity.ai",
            **kwargs
        }
        extra_headers = {
            # "User-Agent": self.headers.get("User-Agent"),
            "Cookie": self._get_cookies_str(),
            **kwargs.get("extra_headers", {})
        }
        if not extra_headers["Cookie"]:
            del extra_headers["Cookie"]
        kwargs["extra_headers"] = extra_headers

        async def _():
            ws = await websockets.connect(
                url,
                **kwargs
            )
            # print(ws.request_headers)
            self.ws = ws
            return ws
        return self.run_task(_)

    def get_json(self, file="test_session", value=None):
        try:
            with open(f"{file}.json", "r+" if not value else "w", encoding="utf8") as r:
                if value:
                    r.write(json.dumps(value) if type(
                        value) in [dict, list] else str(value))
                    return value
                js = r.read()
                r.close()
                data = json.loads(js)
                cookies = {}
                if type(data) is list and len(data) and "name" in data[0]:
                    for c in data:
                        cookies[c["name"]] = c["value"]
                return cookies if cookies else data
        except Exception as e:
            print(str(e))
            pass


if __name__ == "__main__":
    # Create a client instance
    session = HttpClient(timeout=60, client_identifier="chrome_117")
    t = format(random.getrandbits(32), "08x")
    j = session.get_json()
    # session.cookies.update(j)
    url = "https://www.perplexity.ai/"
    response = session.get(url)
    print(response.status_code)
    print(session.cookies.get_dict())
    # url = "https://www.perplexity.ai/api/auth/session"
    # response = session.get(url)
    # print(response.text)
    # url = f"https://www.perplexity.ai/socket.io/?EIO=4&transport=polling&t={t}"
    # response = session.get(url)
    # socket = json.loads(response.text[1:])
    # sid = socket["sid"]
    # socket = {
    #     "ping_interval": socket["pingInterval"],
    #     "ping_timeout": socket["pingTimeout"],
    # }
    # url = f"https://www.perplexity.ai/socket.io/?EIO=4&transport=polling&t={t}&sid={sid}"
    # response = session.post(
    #     url=url,
    #     data="40{\"jwt\":\"anonymous-ask-user\"}"
    # )
    # print(response.text)
    # ws_url = f"wss://www.perplexity.ai/socket.io/?EIO=4&transport=websocket&sid={sid}"
    # session.wss_connect(ws_url, **socket)
    # print(session.wss_send("2probe"))
    # print(session.wss_send("5"))
    # message = "421" + json.dumps([
    #     "perplexity_ask",
    #     "websockets.exceptions.InvalidStatusCode: server rejected WebSocket connection: HTTP 400",
    #     {
    #         "version": "2.9",
    #         "source": "default",
    #         "attachments": [],
    #         "language": "en-US",
    #         "timezone": "Africa/Cairo",
    #         "search_focus": "internet",
    #         "frontend_uuid": "c239bbc4-7692-445a-b101-a6a466beecbb",
    #         "mode": "concise",
    #         "is_related_query": False,
    #         "is_default_related_query": False,
    #         "visitor_id": "f37ebed7-66a0-4c2d-8642-a295b280ae87",
    #         "user_nextauth_id": "ef054221-dca2-4687-a2eb-4c852abd1765",
    #         "frontend_context_uuid": "9b6f2f28-8c79-41fa-8a89-d0c6ff311ef3",
    #         "prompt_source": "user",
    #         "query_source": "home",
    #         "is_incognito": False
    #     }
    # ])
    # session.wss_send(message)
    # while (message := session.wss_recv()) is not None:
    #     print(message)
    # print(session.wss_recv())

    # session.headers.update({
    #     "Referer": "https://duckduckgo.com/",
    # })
    # # # # Make a synchronous GET request
    # response = session.get(
    #     "https://links.duckduckgo.com/d.js?q=how+do+i+enable+mtp+on+my+samsung&kl=us-en&l=us-en&p=&s=0&df=&bing_market=us-EN&ex=-2&vqd=4-146358820706598297029154084323688488002")

    # print("Status:", response.status_code)
    # print("Headers:", session.headers.get_dict())
    # print("Headers:", response.headers)
    # print("Cookies:", response.cookies.get_dict())
    # print(response.text)
    session.close()
