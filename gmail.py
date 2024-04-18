# import the required libraries
import time
import tls_client
import json
import random
import re
import requests


def getEmails(fromemail="noreply@tm.openai.com"):
    pass


class Emailnator:
    def __init__(self, domain=False, plus=False, dot=True, google_mail=False):
        # inbox_ads for exclude the advertisements when you create a new mail
        self.inbox = []
        self.inbox_ads = []
        self.domain = domain
        self.plus = plus
        self.dot = dot
        self.google_mail = google_mail
        self.email = None
        # create session with provided headers & cookies
        # self.s = requests.Session()
        self.s = tls_client.Session(
            client_identifier="chrome112",
            random_tls_extension_order=True,
            debug=False
        )

    def getTempEmail(self, args={}):
        domain = args.get("domain", self.domain)
        plus = args.get("plus", self.plus)
        dot = args.get("dot", self.dot)
        google_mail = args.get("google_mail", self.google_mail)
        self.s.get("https://www.emailnator.com/")
        TOKEN = self.s.cookies.get_dict()["XSRF-TOKEN"]
        TOKEN = TOKEN.replace("%3D", "=")
        self.s.headers.update({
            'origin': 'https://www.emailnator.com',
            'referer': 'https://www.emailnator.com/',
            'sec-ch-ua': '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest',
            'x-xsrf-token': TOKEN,
        })
        data = {'email': []}
        if domain:
            data['email'].append('domain')
        if plus:
            data['email'].append('plusGmail')
        if dot:
            data['email'].append('dotGmail')
        if google_mail:
            data['email'].append('googleMail')

        # generate temporary email address
        try:
            self.email = self.s.post(
                'https://www.emailnator.com/generate-email', json=data).json()['email'][0]

            # append advertisements to inbox_ads
            for ads in self.s.post('https://www.emailnator.com/message-list', json={'email': self.email}).json()['messageData']:
                self.inbox_ads.append(ads['messageID'])
        except Exception as e:
            print("getEmail error:", str(e))
        return self.email

    def getMessages(self, f=None, wait=True, retry_timeout=1, max_retry=20):
        self.new_msgs = []
        retry_count = 0
        try:
            while True:
                for msg in self.s.post('https://www.emailnator.com/message-list', json={'email': self.email}).json()['messageData']:
                    if not f or f and msg["from"].find(f) != -1:
                        if msg['messageID'] not in self.inbox_ads and msg not in self.inbox:
                            msg = self.open(msg['messageID'])
                            msg = self.getLink(msg)
                            if msg:
                                self.new_msgs.append(msg)
                retry_count += 1
                if wait and retry_count < max_retry and not self.new_msgs:
                    time.sleep(retry_timeout)
                else:
                    break
            self.inbox += self.new_msgs
        except Exception as e:
            print("getMessages error:", str(e))
        return self.new_msgs

    def getLink(self, body):
        paterns = [
            'href="([^"]*?\/(?:verify|activate|click\?|email_confirmed|email)[^"]*?)"',
            "<td.*?<div[^><]*?>(\d+)<\/div>",
            "into your browser\:\s+(https:.*?)\s",
            '(http[^"]*?\/(?:activate|callbackUrl)[^"]*?)\s',
            "\((.*?http.*?)\)",
        ]
        for ra in paterns:
            regex = fr"{ra}"
            # print(regex)
            m5 = re.search(regex, str(body), re.MULTILINE | re.DOTALL)
            if m5:
                l = m5.group(1).strip()
                return l if l[:4].find("http") != -1 else None
        return None
    # open selected inbox message

    def open(self, msg_id):
        return self.s.post('https://www.emailnator.com/message-list', json={'email': self.email, 'messageID': msg_id}).text


class temp_mail():
    def __init__(self, email=None, create=False, gmail=False) -> None:
        self.email = email
        self.gmail = None
        self.gmail_email = gmail
        self.Emailnator = Emailnator()
        self.last_email = []
        self.temp = None
        self.create = create
        self.client = tls_client.Session(
            client_identifier="chrome112",
            random_tls_extension_order=True,
            debug=False
        )
        pass

    def deleteEmail(self):
        if not self.email or self.gmail_email:
            return None
        j = None
        try:
            url = "https://app.restoviebelle.com/openai.php?get=deleteTempMail&email=" + self.email
            response = requests.request("GET", url)
            j = json.loads(response.text)
            print("deleteEmail:", self.email)
        except Exception as e:
            print("DeleteEmail Error:", str(e))
        self.email = None
        # print(j)
        return j

    def getMessages(self, f="", wait=False):
        if self.gmail_email:
            return self.Emailnator.getMessages(f, wait=wait)
        response = None
        try:
            rea = None
            max_retry = 20
            retry_count = 0
            url = f"https://app.restoviebelle.com/openai.php?get=getEmailMessages&from={f}"
            if self.email:
                url += "&email="+self.email
            if self.temp:
                url += "&temp="+self.temp
            url = url.strip()
            print(url)
            while True:

                response = self.client.get(url)
                txt = response.text
                if txt is None:
                    rea = None
                else:
                    rea = response.json()
                    if len(rea) < 1:
                        rea = None
                if not rea and wait and retry_count < max_retry:
                    retry_count += 1
                    time.sleep(1)
                    continue
                if rea:
                    print(rea)
                return rea
        except Exception as e:
            # print(response.text)
            print("getMessages Error:", str(e), response)
        return rea

    def all_in_list(self, tempemails):
        last_activation = self.last_email
        rea = []
        for email in tempemails:
            if email not in last_activation:
                rea.append(email)
        return rea

    def getRandomEmail(self, email=None, check=False):
        tempemails = [
            "contact@theglossylocks.com",
            "admin@snakesnuggles.com",
            "admin@bikebesties.com",
            "mohtasm@everysimply.com",
        ]
        if email:
            e = list(filter(lambda x: email.find(
                x.lower().split("@")[1]) != -1, tempemails))
            if len(e) > 0:
                e = e[0]
                return e
            if check:
                return False
        tempemails = self.all_in_list(tempemails)
        if len(tempemails) < 1:
            self.last_email = []
            return self.getRandomEmail()
        emaile = random.choice(tempemails)
        self.last_email.append(emaile)
        return emaile

    def check_email(self):
        if self.email:
            c = self.getRandomEmail(self.email, check=True)
            if c:
                self.temp = c
                try:
                    url = "https://app.restoviebelle.com/openai.php?get=check_email&email=" + self.email
                    # url += "&user=" + self.email
                    url += "&create=" + str(self.create)
                    response = requests.request("GET", url)
                    j = json.loads(response.text)
                    if j:
                        return True
                except Exception as e:
                    print("check_email error:", str(e))
        return False

    def getAlias(self, user):
        tempemails = [
            "contact@theglossylocks.com",
            "admin@snakesnuggles.com",
            "admin@bikebesties.com",
            "mohtasm@everysimply.com",
        ]
        email = filter(lambda x: user.find(
            x.lower().split("@")[1]) != -1, tempemails)
        email = list(email)[0]
        # print(email)
        self.email = None
        self.temp = email
        try:
            url = "https://app.restoviebelle.com/openai.php?get=getAliasMail&email=" + email
            url += "&user=" + user
            # print(url)
            response = requests.request("GET", url)
            j = json.loads(response.text)
            if j:
                self.email = user
                print("getAlias:", self.email)
        except Exception as e:
            print("getAlias error:", str(e))
        return self.email

    def upGmail(self, **kwargs):
        try:
            if not self.gmail:
                return None
            url = "https://app.restoviebelle.com/openai.php?get=upGmail"
            kwargs["email"] = self.gmail["email"]
            for key, value in kwargs.items():
                if key == "uses" and self.gmail["uses"]:
                    uses = self.gmail["uses"].split(",")
                    uses.append(value)
                    value = ",".join(uses)
                url += "&" + key + "=" + value
            response = requests.request("GET", url)
            j = json.loads(response.text)
            if j:
                print(j)
                return j
        except Exception as e:
            print("upGmail error:", str(e))
        return None

    def getGmail(self, **kwargs):
        # email = kwargs.get("email", None)
        try:
            url = "https://app.restoviebelle.com/openai.php?get=getGmail"
            for key, value in kwargs.items():
                url += "&" + key + "=" + value
            response = requests.request("GET", url)
            j = json.loads(response.text)
            if j:
                self.gmail = j[0]
                return j
                print("getEmail:", self.email)
        except Exception as e:
            print("getGmail error:", str(e))
        return None

    def setData(self, table, **kwargs):
        # email = kwargs.get("email", None)
        try:
            url = "https://app.restoviebelle.com/openai.php?set="+table
            # for key, value in kwargs.items():
            #     url += "&" + key + "=" + value
            response = requests.request("POST", url, data=kwargs)
            print(response.text)
            j = json.loads(response.text)
            if j:
                return j
        except Exception as e:
            print("setData error:", str(e))
        return None

    def getData(self, table, **kwargs):
        # email = kwargs.get("email", None)
        try:
            url = "https://app.restoviebelle.com/openai.php?get="+table
            for key, value in kwargs.items():
                url += "&" + key + "=" + value
            response = requests.request("POST", url, data=kwargs)
            j = json.loads(response.text)
            if j:
                return j
        except Exception as e:
            print("getData error:", str(e))
        return None

    def getEmail(self, email="mohtasm@everysimply.com", gmail=False, **args):
        self.gmail_email = gmail or self.gmail_email
        if self.gmail_email:
            return self.Emailnator.getTempEmail(args)
        if self.check_email():
            return self.email
        if not email:
            email = self.getRandomEmail(self.email)
        self.temp = email
        try:
            url = "https://app.restoviebelle.com/openai.php?get=getTempMail&email=" + email
            response = requests.request("GET", url)
            j = json.loads(response.text)
            if j:
                self.email = j["email"]
                # print("getEmail:", self.email)
        except Exception as e:
            print("getEmail error:", str(e))
        return self.email


# temp = temp_mail()
# d = temp.getData("scrapingant")
# print(d)
# e = temp.getEmail()
# print(e)
# temp.email = "loheru.huveheki@everysimply.com"
# code = temp.getMessages(
#     "platform@stability.ai")
# print(code)

# headers = {
#     'Origin': 'https://bard.google.com"',
#     # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
#     # 'Content-Type': 'application/json',
#     'Cookie': 'SID=Zgjehk9Szy4yAnKqK5LkeTxEHHrPDb75LRJ3p6zvB2CTMBO7t8BaBcKiUGRI-W5Ljj6cew.; __Secure-1PSID=Zgjehk9Szy4yAnKqK5LkeTxEHHrPDb75LRJ3p6zvB2CTMBO7-yffvrd728sTgRkC2GS1dA.; __Secure-3PSID=Zgjehk9Szy4yAnKqK5LkeTxEHHrPDb75LRJ3p6zvB2CTMBO7fVZe-T8452ECLiMH4QWQhA.; HSID=AoXbZvVpgFE-InmJQ; SSID=A911RevnyLBjtsYO2; APISID=yZosJXsMzy5uZvXY/AMsvWDKn-OG34q2c1; SAPISID=R9wPhsO3158b7SVc/A3Hh1jE8_GWeeo3-G; __Secure-1PAPISID=R9wPhsO3158b7SVc/A3Hh1jE8_GWeeo3-G; __Secure-3PAPISID=R9wPhsO3158b7SVc/A3Hh1jE8_GWeeo3-G; SEARCH_SAMESITE=CgQI_pgB; OGPC=19036484-1:19022519-1:19031986-1:; 1P_JAR=2023-08-17-19; AEC=Ad49MVEaWPRfIyWjyUtxffeG9Laj1v29IVTPTIbJdGTiEUfFamix4-5DQMg; NID=511=dRYe4O92DN38wiN-aoUXv2Dt9SL7ESB0CvCuliPGRYt0vUGcAOhP8I_FylPdfcRIX6o8emdM5szLUCFgYHvmdwg2f19TtcLxaVmpXAb_ebT_ueUrrlKgQ-T-hVMY7Uav2UAZhnyKyHRPnGZUWKj7s0piue5bRKqUGHT165CzXYqieHH5iiXS-FhD_Www_X9FlAMeOniLZh9oqO8nXzN-dY7oj8sZcQZhBehhpL5ez_qIfxq4KxAMmjqcP1a6VZbwa3FBcIf8td61HrI9Igq42i_fz7kTrTphKW4ivx5fE1uE1SVXaCKJ_izAHQxKUZR_9cOdHH5pUO_HeN1tqUP3Krwku6gEbJId8c5VKN7s; __Secure-1PSIDTS=sidts-CjIBSAxbGcqkqhPl-FH3KD_JD0m7Mhh4m5T3YTgEsAPaAhPjnS-OmfuUcmzR9d6LawO8wRAA; __Secure-3PSIDTS=sidts-CjIBSAxbGcqkqhPl-FH3KD_JD0m7Mhh4m5T3YTgEsAPaAhPjnS-OmfuUcmzR9d6LawO8wRAA; SIDCC=APoG2W-8tUz-D6s8zd1nb2bBdy1I2OvD2q632S4UR9C2h2y9LAZhYYIBfWJ40kBzpO5PXAQEp4s; __Secure-1PSIDCC=APoG2W_h2f4qAqyskPhUa-P30khFSn7NSC3vJGb5QmxicBPxgthtiREB-JSejzLReBWxHsQomQ; __Secure-3PSIDCC=APoG2W8k9tH-qXxun-qcix7u7ocD5k73Ym0jnxsuJ-jR7dCWmM4rt09mhsHevvOftAhDFL7ebJw'
# }

# session = tls_client.Session(
#     client_identifier="chrome112",
#     random_tls_extension_order=True
# )
# url = "https://bard.google.com/"
# response = session.get(url, headers=headers)

# print(response)
# print(response.text)

# code = getEmails("support@scrapeowl.com")
# print(code)
# code = getEmails("support@mail.anthropic.com")
# print(code)
# code = getEmails("noreply@google.com")
# print(code)

# code = getEmails("forwarding-noreply@google.com")
# print(code)
