import asyncio
# from twisted.internet import ssl, reactor
# from autobahn.asyncio.websocket import WebSocketClientFactory, WebSocketClientProtocol, connectWS
import base64
import json
import logging
import os
import random
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from requests import Response

from constants import DELIMETER
# import tls_client
import pyreqwest_impersonate as pri  # type: ignore

from http_client import HttpClient

logging.basicConfig(level=logging.ERROR)


def fix_headers(r):
    headers = {}
    if r:
        for v in r:
            if type(r) is list:
                vf = str(v).split(":")
                if len(vf) < 2:
                    continue
                k = vf[0].strip()
                v = vf[1].strip()
            else:
                k = v
                v = r[v]
            k = map(lambda x: x.title(), k.split("-"))
            k = "-".join(k)
            if v:
                headers[k] = v
    return headers


def convert_json(cookies):
    try:
        cookies = base64.b64decode(cookies).decode("utf-8")
    except:
        pass
    try:
        if cookies and type(cookies) is str:
            cookies = json.loads(cookies)
    except Exception as e:
        pass
    return cookies


def _get_cookies_str(dcookies: dict) -> str:
    cookies = ""
    scookies = {}
    dcookies = convert_json(dcookies)
    if not dcookies:
        return dcookies
    if type(dcookies) is list:
        for c in dcookies:
            scookies[c["name"]] = c["value"]
        dcookies = scookies
    for key, value in dcookies.items():
        cookies += f"{key}={value}; "
    return cookies[:-2]


def get_http_client(*args, **kwargs) -> HttpClient:
    headers = kwargs.get("headers", {})
    if not headers:
        headers = {
            "Referer": "https://duckduckgo.com/",
            "User-Agent": get_useragent()
        }
    brower = kwargs.get("brower", "chrome_120")
    headers = fix_headers(headers)
    timeout = kwargs.get("timeout", 30)
    session = HttpClient(**kwargs)
    # session.timeout_seconds = timeout
    # session = Session(impersonate="chrome124", timeout=timeout)
    # session.headers.update(headers)
    return session

    return pri.Client(
        headers=headers,
        timeout=timeout,
        cookie_store=True,
        referer=True,
        impersonate=brower,
        follow_redirects=False,
        verify=False
    )


def get_cookies_dict(responce: Response):
    cookies = responce.cookies
    if hasattr(cookies, "get_dict"):
        return cookies.get_dict()
    return {k: v for k, v in cookies.items()}


def get_dict(responce: Response):
    headers = responce
    if hasattr(headers, "get_dict"):
        return headers.get_dict()
    return {k: v for k, v in headers.items()}


def get_headers_dict(responce: Response):
    headers = responce.headers
    if hasattr(headers, "get_dict"):
        return headers.get_dict()
    return {k: v for k, v in headers.items()}


def http_get(url, headers={}):
    r = None
    html = None
    try:
        r = get_http_client(headers=headers)
        rs = r.get(url)
        if rs.status_code == 200:
            if not in_str(rs.text):
                html = rs.text
        r.close()
        return html
    except Exception as e:
        print(f"http_get: {e}")
    finally:
        if r:
            r.close()
    return None


def get_useragent():

    _useragent_list = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.62',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0'
    ]
    return random.choice(_useragent_list)


def get_word_count(self, text):
    counts = len(re.findall(r'\w+', text))
    return counts


def save_html(content, path="output1.html"):
    with open(path, "w",  encoding="utf8") as file:
        file.write(str(content))
        file.close()


def is_path(infile):
    if os.path.isdir(infile) or os.path.exists(infile):
        return True
    return False


def load_html(html_path: str) -> BeautifulSoup:
    try:
        if is_path(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                html_path = f.read()
        return BeautifulSoup(html_path, "html.parser", from_encoding="utf-8")
    except FileNotFoundError:
        print(f"File not found: {html_path}")
    except Exception as e:
        print(f"Error loading HTML: {e}")


def get_json(content):
    try:
        return json.loads(content)
    except Exception as e:
        pass
    return None


def as_json(message: dict) -> str:
    """
    Convert message to JSON, append delimeter character at the end.
    """
    return json.dumps(message) + DELIMETER


def in_str(string, arr=None, lower=True):
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


def cookies_as_dict(cookies: str) -> dict:
    """
    Convert a string of cookies into a dictionary.
    """
    return {
        key_value.strip().split("=")[0]: "=".join(key_value.split("=")[1:])
        for key_value in cookies.split(";")
    }


def check_if_url(string: str) -> bool:
    parsed_string = urlparse(string)
    if parsed_string.scheme and parsed_string.netloc:
        return True
    return False


# class MyClientProtocol(WebSocketClientProtocol):
#     def onConnect(self, response):
#         print("Server connected: {0}".format(response.peer))

#     def onOpen(self):
#         print("WebSocket connection open.")

#     def onMessage(self, payload, isBinary):
#         print("Received message: {0}".format(payload.decode('utf8')))

#     def onClose(self, wasClean, code, reason):
#         print("WebSocket connection closed: {0}".format(reason))


# if __name__ == '__main__':
#     url = "wss://your.websocket.server/path"
#     hostname = "your.websocket.server"

#     factory = WebSocketClientFactory(url)
#     factory.protocol = MyClientProtocol

#     context_factory = ssl.optionsForClientTLS(hostname)
#     connectWS(factory, context_factory)
# factory.M
#     reactor.run()

# response = get_http_client().get("https://scrapeops.io/app/headers")

# print("Status:", response.status_code)
# print("Headers:", response.headers)
# print("Cookies:", response.cookies.get_dict())

# save_html(response.text)
