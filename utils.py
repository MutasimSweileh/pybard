import base64
import json
import os
import random
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from constants import DELIMETER
import pyreqwest_impersonate as pri  # type: ignore
import tls_client
import requests


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


def get_http_client(*args, **kwargs) -> tls_client.Session:
    headers = kwargs.get("headers", {
        "Referer": "https://duckduckgo.com/"
    })
    brower = kwargs.get("brower", "chrome_120")
    headers = fix_headers(headers)
    timeout = kwargs.get("timeout", 30)
    return requests.Session()
    session = tls_client.Session(
        client_identifier=brower,
        random_tls_extension_order=True,
        debug=False
    )
    session.timeout_seconds = timeout
    session.headers.update(headers)
    return session


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
