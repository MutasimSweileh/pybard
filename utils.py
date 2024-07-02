import json
import os
import random
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from constants import DELIMETER
# import tls_client
import pyreqwest_impersonate as pri  # type: ignore

import requests


def get_http_client(*args, **kwargs) -> requests:
    headers = kwargs.get("kwargs", {
        "Referer": "https://duckduckgo.com/"
    })
    timeout = kwargs.get("timeout", 30)
    return pri.Client(
        headers=headers,
        timeout=timeout,
        cookie_store=True,
        referer=True,
        impersonate="chrome_124",
        follow_redirects=False,
        verify=False,
    )


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
