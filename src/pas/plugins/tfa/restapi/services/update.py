from pas.plugins.tfa.helpers import validate_token
from plone.restapi import _
from plone.restapi.deserializer import json_body
from plone.restapi.services.users.update import UsersPatch as UsersPatchBase

import json


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
                return self._error(
                    400,
                    "Bad Request",
                    _("OTP Value is invalid"),
                )
        # Fix the JSON in Body, UsersPatch from plone.restapi consume the BODY
        #
        # user.setMemberProperties(mapping={key: value}, force_empty=True) fails
        # if a key not in properties
        del data["two_factor_authentication_otp"]
        self.request.set("BODY", json.dumps(data))
        return super().reply()
