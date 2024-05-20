from pas.plugins.tfa.tests.base import FunctionalBase

import transaction


class ServiceEndpointUserUpdateFunctionalTest(FunctionalBase):

    def setUp(self):
        self.portal = self.layer["portal"]
        acl_users = self.portal.acl_users

        # add a testuser
        self.userid = "user1"
        self.pwd = "secret"
        acl_users.userFolderAddUser(self.userid, self.pwd, ["Member"], [])
        transaction.commit()

    def test_userpatch(self):
        import json
        import pyotp
        import requests

        member = self._getMember(self.userid)

        # enable 2fa
        member.setMemberProperties(mapping={"two_factor_authentication_enabled": True})

        transaction.commit()

        # login
        response = requests.post(
            f"{self.portal.absolute_url()}/@login",
            headers={"Accept": "application/json"},
            json={"login": self.userid, "password": self.pwd},
        )
        transaction.commit()

        # extract the secret
        data = json.loads(response.text)
        secret = self._extract_secret(data.get("qr_code"))

        # get the current otp token
        otp = pyotp.TOTP(secret).now()

        # login with 2FA
        response = requests.post(
            f"{self.portal.absolute_url()}/@login",
            headers={"Accept": "application/json"},
            json={"login": self.userid, "otp": otp},
        )
        transaction.commit()

        data = json.loads(response.text)

        # get the jwt token
        token = data.get("token")

        # get the current otp token
        otp = pyotp.TOTP(secret).now()

        # start a session as authenticated user
        session = requests.Session()
        session.headers.update(
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
            }
        )

        # send a patch for member data
        response = session.patch(
            f"{self.portal.absolute_url()}/@users/{self.userid}",
            json={
                "two_factor_authentication_enabled": True,
                "two_factor_authentication_secret": secret,
                "two_factor_authentication_otp": otp,
            },
        )
        self.assertTrue(response.ok)
        self.assertEqual(204, response.status_code)

    def test_userpatch_with_invalid_otp_token(self):
        import json
        import pyotp
        import requests
        import time

        member = self._getMember(self.userid)

        # enable 2fa
        member.setMemberProperties(mapping={"two_factor_authentication_enabled": True})

        transaction.commit()

        # login
        response = requests.post(
            f"{self.portal.absolute_url()}/@login",
            headers={"Accept": "application/json"},
            json={"login": self.userid, "password": self.pwd},
        )
        transaction.commit()

        # extract the secret
        data = json.loads(response.text)
        secret = self._extract_secret(data.get("qr_code"))

        # get the current otp token
        otp = pyotp.TOTP(secret).now()

        # login with 2FA
        response = requests.post(
            f"{self.portal.absolute_url()}/@login",
            headers={"Accept": "application/json"},
            json={"login": self.userid, "otp": otp},
        )
        transaction.commit()

        data = json.loads(response.text)

        # get the jwt token
        token = data.get("token")

        # get the current otp token
        otp = pyotp.TOTP(secret).now()

        # wait until the token is invalid
        time.sleep(40)

        # start a session as authenticated user
        session = requests.Session()
        session.headers.update(
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
            }
        )

        # send a patch for member data
        response = session.patch(
            f"{self.portal.absolute_url()}/@users/{self.userid}",
            json={
                "two_factor_authentication_enabled": True,
                "two_factor_authentication_secret": secret,
                "two_factor_authentication_otp": otp,
            },
        )

        self.assertFalse(response.ok)
        self.assertEqual(400, response.status_code)

    def test_userpatch_properties_untouched(self):
        import json
        import requests

        memberProperties = self._getMemberProperties(self.userid)
        del memberProperties["last_login_time"]  # not needed for comparison
        del memberProperties["login_time"]  # not needed for comparison

        # login
        response = requests.post(
            f"{self.portal.absolute_url()}/@login",
            headers={"Accept": "application/json"},
            json={"login": self.userid, "password": self.pwd},
        )
        transaction.commit()

        data = json.loads(response.text)

        # get the jwt token
        token = data.get("token")

        # start a session as authenticated user
        session = requests.Session()
        session.headers.update(
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
            }
        )

        # send a patch for member data with property 2FA disabled
        response = session.patch(
            f"{self.portal.absolute_url()}/@users/{self.userid}",
            json={
                "two_factor_authentication_enabled": False,
                "two_factor_authentication_otp": "12345678",
            },
        )
        self.assertTrue(response.ok)
        self.assertEqual(204, response.status_code)
        transaction.commit()

        patchedMemberProperties = self._getMemberProperties(self.userid)
        del patchedMemberProperties["last_login_time"]  # not needed for comparison
        del patchedMemberProperties["login_time"]  # not needed for comparison

        self.assertEqual(
            memberProperties,
            patchedMemberProperties,
            "Member properties should be equal",
        )
