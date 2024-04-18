import json
import google.generativeai as genai
from flask import Flask, jsonify, make_response, request as rq
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import requests
app = Flask(__name__)

auth = HTTPBasicAuth()

users = {
    "mohtasm": generate_password_hash("mohtasm10Q@@"),
    "susan": generate_password_hash("bye")
}


@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username


@app.route("/request", methods=['POST', 'GET'])
@auth.login_required
def request():
    data = rq.get_json()
    data = {**rq.form, **rq.args, **data}
    url = data.get("url", None)
    headers = data.get("headers", {})
    d = data.get("data", None)
    method = data.get("method", "POST" if d else "GET")

    def fix_head(r):
        headers = {}
        for v in r:
            v = str(v).split(":")
            headers[v[0]] = v[1]
            return headers
    headers = fix_head(headers)
    j = headers.get("Content-Type", None)
    j = headers.get("content-type", j)
    if j and j.find("json") != -1:
        d = json.dumps(d)
    try:
        response = requests.request(method, url, headers=headers, data=d)
        d = {
            'success': True,
            'data': response.text
        }
    except Exception as e:
        m = str(e)
        d = {
            'success': False,
            'error': m
        }
    return jsonify(d)


@app.route("/bard", methods=['POST', 'GET'])
@auth.login_required
def bard():
    data = rq.get_json()
    data = {**rq.form, **rq.args, **data}
    bard = ai_bard(data)
    return jsonify(bard)


def ai_bard(data):
    key = data.get("key")
    model_name = data.get("model", "gemini-1.5-pro-latest")
    prompt = data.get("prompt", None)
    try:
        genai.configure(api_key=key)
        generation_config = data.get("generation_config", {
            "temperature": 0.9,
            "top_p": 1,
            "top_k": 1,
            "max_output_tokens": 2048,
        })
        safety_settings = data.get("safety_settings", [
            {
                "category": "HARM_CATEGORY_HARASSMENT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE"
            },
            {
                "category": "HARM_CATEGORY_HATE_SPEECH",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE"
            },
            {
                "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE"
            },
            {
                "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE"
            },
        ])

        model = genai.GenerativeModel(model_name=model_name,
                                      generation_config=generation_config,
                                      safety_settings=safety_settings)
        prompt_parts = [
            prompt
        ]
        response = model.generate_content(prompt_parts)
        return {
            'success': True,
            'data': response.text
        }
    except Exception as e:
        m = str(e)
        return {
            'success': False,
            'error': m
        }


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
