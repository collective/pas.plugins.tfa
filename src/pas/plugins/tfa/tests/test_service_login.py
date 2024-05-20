from pas.plugins.tfa.tests.base import FunctionalBase
from plone.app.testing import setRoles
from plone.app.testing import TEST_USER_ID
from plone.app.testing import TEST_USER_NAME
from plone.app.testing import TEST_USER_PASSWORD

import transaction


class ServiceEndpointLoginFunctionalTest(FunctionalBase):

    def setUp(self):
        self.portal = self.layer["portal"]
        setRoles(self.portal, TEST_USER_ID, ["Member"])

    def test_login_without_2FA(self):
        import requests

        # login without "2FA"
        response = requests.post(
            f"{self.portal.absolute_url()}/@login",
            headers={"Accept": "application/json"},
            json={"login": TEST_USER_NAME, "password": TEST_USER_PASSWORD},
        )
        transaction.commit()

        self.assertIn("token", response.text)

    def test_login_with_2FA(self):
        import json
        import pyotp
        import requests

        member = self._getMember(TEST_USER_NAME)

        # enable 2fa
        member.setMemberProperties(mapping={"two_factor_authentication_enabled": True})

        transaction.commit()

        # login
        response = requests.post(
            f"{self.portal.absolute_url()}/@login",
            headers={"Accept": "application/json"},
            json={"login": TEST_USER_NAME, "password": TEST_USER_PASSWORD},
        )
        transaction.commit()

        data = json.loads(response.text)
        self.assertIn("action", data.keys())
        self.assertIn("login", data.keys())
        self.assertIn("qr_code", data.keys())
        self.assertIn("type", data.keys())
        self.assertIn("add", data.get("action"))
        self.assertIn(TEST_USER_ID, data.get("login"))
        self.assertIn("otpauth://", data.get("qr_code"))
        self.assertIn("totp", data.get("type"))

        # extract the secret
        data = json.loads(response.text)
        secret = self._extract_secret(data.get("qr_code"))

        # get the current otp token
        otp = pyotp.TOTP(secret).now()

        # login with 2FA
        response = requests.post(
            f"{self.portal.absolute_url()}/@login",
            headers={"Accept": "application/json"},
            json={"login": TEST_USER_NAME, "otp": otp},
        )
        transaction.commit()
        self.assertIn("token", response.text)
