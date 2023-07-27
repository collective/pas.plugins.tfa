# -*- coding: utf-8 -*-
from plone.restapi.deserializer import json_body
from plone.restapi.services.auth.login import Login as BaseLogin
from plone.restapi.services.auth.renew import Renew
from plone import api
from zope.annotation.interfaces import IAnnotations
from pas.plugins.tfa.interfaces import OTP_CHALLENGE_KEY


class Login(BaseLogin):
    def reply(self):
        data = json_body(self.request)
        otp_challenge = IAnnotations(self.request).get(OTP_CHALLENGE_KEY)
        if otp_challenge:
            return {
                "action": otp_challenge.get("action", "challenge"),
                "type": otp_challenge.get("type"),
                "login": otp_challenge.get("login"),
                "form": self.request.form,
                "qr_code": otp_challenge.get("qr_code"),
                "data": otp_challenge,
            }
        if "otp" in data and not api.user.is_anonymous():
            # user is authenticated with pas, generate a new auth_token
            return Renew.reply(self)
        return super().reply()
