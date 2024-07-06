import json
import os
from flask import Flask, Request, jsonify, make_response, request
from flask_httpauth import HTTPBasicAuth
from captcha import Captcha
import perplexity as perplexityapi
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

from utils import _get_cookies_str, fix_headers, get_headers_dict, get_http_client
load_dotenv()

app = Flask(__name__)

auth = HTTPBasicAuth()

users = {
    "mohtasm": generate_password_hash("mohtasm10Q@@"),
    "susan": generate_password_hash("bye")
}


def get_fix_form(request: Request):
    data = {}
    if not request:
        return data
    try:
        data = json.loads(request.data, strict=False)
    except:
        pass
    data = {**request.form, **request.args, **data}
    for k, v in data.items():
        if type(v) is not str:
            continue
        v = v.strip()
        if not v or v == "0" or v == "false" or v == "none" or v == "null":
            data[k] = False
        if v == "1" or v == "true":
            data[k] = True
    return data


def fix_head(r):
    headers = {}
    for v in r:
        vf = str(v).split(":")
        headers[vf[0].strip()] = vf[1].strip()
    return headers


@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username


@app.route("/captcha", methods=['POST', 'GET'])
@auth.login_required
def captcha():
    data = get_fix_form(request)
    try:
        c = Captcha()
        c = c.handle_requsts(**data)
        d = {
            'success': True,
            'data': c
        }
    except Exception as e:
        m = str(e)
        d = {
            'success': False,
            'error': m
        }
    return jsonify(d)


@app.route("/send", methods=['POST', 'GET'])
@app.route("/request", methods=['POST', 'GET'])
@auth.login_required
def requesta():
    data = get_fix_form(request)
    url = data.get("url", None)
    brower = data.get("brower", "chrome_120")
    timeout = data.get("timeout", 30)
    headers = data.get("headers", {})
    cookies = data.get("cookies", None)
    d = data.get("data", None)
    method = data.get("method", "POST" if d else "GET")
    headers = fix_headers(headers)
    j = headers.get("Content-Type", None)
    if cookies:
        headers["Cookie"] = _get_cookies_str(cookies)
    pas = {
        "url": url
    }
    if headers:
        pas["headers"] = headers
    if j and j.find("json") != -1:
        pas["json"] = d
    elif d:
        pas["data"] = d
    try:
        session = get_http_client(timeout=timeout, brower=brower)
        if method == "GET":
            response = session.get(**pas)
        else:
            response = session.post(**pas)
        d = {
            'success': True,
            "status_code": response.status_code,
            "headers": response.headers,
            "cookies": response.cookies,
            'data': response.text
        }
    except Exception as e:
        m = str(e)
        d = {
            'success': False,
            'error': m
        }
    return jsonify(d)


@app.route("/perplexity", methods=['POST', 'GET'])
@auth.login_required
def perplexity():
    data = {**request.form, **request.args}
    sessionKey = data.get("sessionKey", None)
    conversationId = data.get("conversationId", None)
    debug = data.get("debug", False)
    use_driver = data.get("use_driver", False)
    focus = data.get("focus", "internet")
    prompt = data.get("prompt", None)
    mode = data.get("mode", "copilot")
    email = data.get("email", None)
    try:
        perplexity = perplexityapi.Perplexity(
            cookies=sessionKey, email=email, debug=debug, use_driver=use_driver)
        answer = perplexity.search_sync(prompt, mode=mode, focus=focus)
        data = {
            'success': True,
            'data': answer
        }
    except perplexityapi.CustomException as e:
        data = {
            'success': False,
            **e.getJSON()
        }
    return jsonify(data)


@app.errorhandler(404)
def not_found(error):
    # resp = make_response("404", 404)
    # resp.headers['X-Something'] = 'A value'
    status = 500
    message = 'Whoops!! something went wrong'
    return jsonify(
        status=status,
        message=message
    ), 500


if __name__ == '__main__':
    app.debug = True
    app.run(port=8090, use_reloader=False, debug=True)
