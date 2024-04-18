import google.generativeai as genai
from flask import Flask, jsonify, make_response, request
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

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


@app.route("/bard", methods=['POST', 'GET'])
@auth.login_required
def bard():
    # "mohtasm.com@gmail.com"
    data = {**request.form, **request.args}
    sessionKey = data.get("sessionKey", None)
    conversationId = data.get("conversationId", None)
    prompt = data.get("prompt", None)
    # openai.headless = False
    bard = ai_bard(data)
    return jsonify(bard)


def ai_bard(data):
    key = data.get("key")
    sessionKey = data.get("sessionKey", None)
    conversationId = data.get("conversationId", None)
    prompt = data.get("prompt", None)
    genai.configure(api_key=key)
    generation_config = {
        "temperature": 0.9,
        "top_p": 1,
        "top_k": 1,
        "max_output_tokens": 2048,
    }
    safety_settings = [
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
    ]
    try:
        model = genai.GenerativeModel(model_name="gemini-1.0-pro",
                                      generation_config=generation_config,
                                      safety_settings=safety_settings)
        prompt_parts = [
            prompt
        ]
        response = model.generate_content(prompt_parts)
        return {
            'success': True,
            'data': response
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
