import json
import os
from flask import Flask, Request, jsonify, make_response, request
from flask_httpauth import HTTPBasicAuth
from captcha import Captcha
from exceptions import CustomException
import perplexity as perplexityapi
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

from ucwebdriver import UC_Webdriver
from utils import _get_cookies_str, fix_headers, get_dict, get_headers_dict, get_http_client
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


@app.route("/get_html", methods=['POST', 'GET'])
@auth.login_required
def get_html():
    data = get_fix_form(request)
    url = data.get("url", None)
    _json = data.get("json", False)
    if not url or url == "undefined":
        return not_found(None)
    del data["url"]
    try:
        html = UC_Webdriver.get_html(url, **data)
        if _json:
            if not html:
                raise Exception("we could't fetch url!")
            return jsonify({
                'success': True,
                'html': html
            })
        # html = openai.uc_dr.get_html(url,data)
        # html = openai.dr.get_html(url, data)
        return html
    except Exception as e:
        if _json:
            return jsonify({
                'success': False,
                'message': str(e)
            })
    return ""


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
    session = None
    try:
        session = get_http_client(timeout=timeout, brower=brower)
        if method == "GET":
            response = session.get(**pas)
        else:
            response = session.post(**pas)
        session.close()
        d = {
            'success': True,
            "status_code": response.status_code,
            "headers": get_dict(response.headers),
            "cookies": get_dict(response.cookies),
            'data': response.text
        }
    except Exception as e:
        m = str(e)
        d = {
            'success': False,
            'error': m
        }
    finally:
        if session:
            session.close()
    return jsonify(d)


@app.route("/perplexity", methods=['POST', 'GET'])
@auth.login_required
def perplexity():
    data = get_fix_form(request)
    sessionKey = data.get("sessionKey", None)
    conversationId = data.get("conversationId", None)
    focus = data.get("focus", "internet")
    debug = data.get("debug", False)
    use_driver = data.get("use_driver", False)
    prompt = data.get("prompt", None)
    mode = data.get("mode", "concise")
    email = data.get("email", None)
    try:
        _perplexity = perplexityapi.Perplexity()
        _perplexity.init(cookies=sessionKey, email=email,
                         debug=debug, use_driver=use_driver, conversationId=conversationId)
        answer = _perplexity.search_sync(prompt, mode=mode, focus=focus)
        data = {
            'success': True,
            'data': answer
        }
    except CustomException as e:
        data = {
            'success': False,
            **e.getJSON()
        }
    finally:
        _perplexity.close()
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
