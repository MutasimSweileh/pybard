import ast
import base64


class NoConnectionException(Exception):
    pass


class ConnectionTimeoutException(Exception):
    pass


class NoResponseException(Exception):
    pass


class ThrottledRequestException(Exception):
    pass


class CaptchaChallengeException(Exception):
    pass


class ConversationLimitException(Exception):
    pass


class CreateConversationException(Exception):
    pass


class GetConversationsException(Exception):
    pass


class ImageUploadException(Exception):
    pass


class CustomException(Exception):
    def __init__(self, message):
        message = str(message)
        self.message = self._json(message)

    def _json(self, cookies):
        try:
            cookies = base64.b64decode(cookies).decode("utf-8")
        except Exception as e:
            pass
        try:
            if cookies and type(cookies) is str:
                cookies = ast.literal_eval(cookies)
        except Exception as e:
            pass
        return cookies

    def getJSON(self):
        if type(self.message) is dict:
            return self.message
        return {'message': self.message, "success": False}

    def __str__(self):
        m = self.getJSON()
        if 'message' in m:
            return m['message']
        return str(m)
