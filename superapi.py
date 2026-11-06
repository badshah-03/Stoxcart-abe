# -*- coding: utf-8 -*-
import hashlib
import hmac
import json

import requests


class superApi:
    _rootUrl = "https://openapi.stoxkart.com"
    url = {
        "auth.login": "/auth/login",
        "auth.2fa": "/auth/twofa/verify",
        "auth.generate.session": "/auth/token",
    }

    def __init__(self, api_key=None, userId=None, password=None, apisecret=None, auto_login=False):
        self.api_key = api_key
        self.apisecret = apisecret
        self.userId = userId
        self.password = password
        self.requestToken = None
        self.validated_token = None
        self.accessToken = None
        self.signature = None

        if auto_login and self.userId and self.password:
            self._getRequestToken()

    def _generate_url(self, urlKey, queryParam=False):
        if queryParam:
            return "{}{}?api-key={}".format(self._rootUrl, self.url[urlKey], self.api_key)
        return "{}{}".format(self._rootUrl, self.url[urlKey])

    def _request(self, url_key, data, headers=None, queryParam=False):
        url = self._generate_url(url_key, queryParam)
        if headers is None:
            headers = self.getCommonHeader()
        try:
            response = requests.post(url, data=data, headers=headers)
        except Exception as exc:
            raise exc
        return response

    def _checkResponse(self, url_key, response):
        if response.status_code != 200:
            raise Exception(response.content)
        data = json.loads(response.content.decode("utf8"))
        return data

    def _getRequestToken(self):
        if not self.userId or not self.password:
            raise ValueError("userId and password are required to generate a request token.")
        params = {
            "platform": "api",
            "data": {"client_id": self.userId, "password": self.password},
        }
        resp = self._request("auth.login", json.dumps(params), self.getCommonHeader(), True)
        data = self._checkResponse("auth.login", resp)
        self.requestToken = data["data"]["request_token"]
        return self.requestToken

    def validate_2fa(self, totp):
        if not self.requestToken:
            raise ValueError("requestToken is missing. Login first.")
        params = {
            "platform": "api",
            "data": {
                "client_id": self.userId,
                "req_token": self.requestToken,
                "action": "api-key-validation",
                "otp": totp,
            },
        }
        resp = self._request("auth.2fa", json.dumps(params), self.getCommonHeader(), True)
        data = self._checkResponse("auth.2fa", resp)
        self.validated_token = data["data"].get("request_token") or self.requestToken
        self.requestToken = self.validated_token
        return self.validated_token

    def getSignature(self):
        if not self.api_key or not self.requestToken or not self.apisecret:
            raise ValueError("api_key, requestToken and apisecret are required to generate a signature.")
        key1 = (self.api_key + self.requestToken).encode("utf-8")
        key2 = self.apisecret.encode("utf-8")
        self.signature = hmac.new(key1, key2, hashlib.sha256).hexdigest()
        return self.signature

    def generateSession(self):
        if not self.requestToken and self.userId and self.password:
            self._getRequestToken()
        if not self.validated_token and self.requestToken:
            self.validated_token = self.requestToken
        if not self.validated_token:
            raise ValueError("No validated token available. Complete login first.")
        self.getSignature()
        params = {
            "api_key": self.api_key,
            "signature": self.signature,
            "req_token": self.validated_token,
        }
        resp = self._request("auth.generate.session", json.dumps(params), self.getCommonHeader())
        data = self._checkResponse("auth.generate.session", resp)
        self.accessToken = data["data"].get("request_token") or data["data"].get("access_token")
        return self.accessToken

    def getCommonHeader(self):
        return {"Content-Type": "application/json"}
