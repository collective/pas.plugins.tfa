# -*- coding: utf-8 -*-
from plone.restapi.deserializer import json_body
from plone.restapi.services.users.update import UsersPatch as UsersPatchBase
from pas.plugins.tfa.helpers import validate_token


class UsersPatch(UsersPatchBase):
    def reply(self):
        data = json_body(self.request)
        if data.get("two_factor_authentication_enabled") and data.get(
            "two_factor_authentication_secret"
        ):
            # verify the otp
            if not validate_token(
                data["two_factor_authentication_otp"],
                user_secret=data["two_factor_authentication_secret"],
            ):
                raise Exception("Invalid OTP")
        return super().reply()
