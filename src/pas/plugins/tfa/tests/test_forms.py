from pas.plugins.tfa.testing import PAS_PLUGINS_OTP_FUNCTIONAL_TESTING
from pas.plugins.tfa.tests.base import FunctionalBase
from plone.app.testing import setRoles
from plone.app.testing import TEST_USER_ID
from plone.app.testing import TEST_USER_NAME
from plone.app.testing import TEST_USER_PASSWORD


class TestFunctionalForms(FunctionalBase):

    layer = PAS_PLUGINS_OTP_FUNCTIONAL_TESTING

    def _getMember(self, username):

        # that's the plone user
        user = self.portal.acl_users.getUser(username)

        # that's the memberdata object
        member = self.portal.portal_membership.getMemberById(user.getId())

        return member

    def setUp(self):
        self.portal = self.layer["portal"]
        setRoles(self.portal, TEST_USER_ID, ["Member"])

        member = self._getMember(TEST_USER_NAME)

        # enable 2fa
        member.setMemberProperties(mapping={"two_factor_authentication_enabled": True})

        # no secret
        member.setMemberProperties(mapping={"two_factor_authentication_secret": None})

    def test_redirect_login_to_tfadd_form(self):

        member = self._getMember(TEST_USER_NAME)

        secret = member.getProperty("two_factor_authentication_secret")

        # the secret is empty
        self.assertFalse(secret, "The secret should be empty")

        browser = self._anon_browser()
        browser.open(f"{self.portal.absolute_url()}/login")
        browser.getControl(name="__ac_name").value = TEST_USER_NAME
        browser.getControl(name="__ac_password").value = TEST_USER_PASSWORD
        browser.getControl(name="buttons.login").click()

        # the form url contain tfa-add
        self.assertIn("@@tfa-add", browser.url)

    def test_tfaddform_login_process(self):
        import pyotp

        member = self._getMember(TEST_USER_NAME)

        secret = member.getProperty("two_factor_authentication_secret")

        # the secret is empty
        self.assertFalse(secret, "The secret should be empty")

        browser = self._anon_browser()
        browser.open(f"{self.portal.absolute_url()}/login")
        browser.getControl(name="__ac_name").value = TEST_USER_NAME
        browser.getControl(name="__ac_password").value = TEST_USER_PASSWORD
        browser.getControl(name="buttons.login").click()

        member = self._getMember(TEST_USER_NAME)
        secret = member.getProperty("two_factor_authentication_secret")

        # the secret is not empty
        self.assertTrue(secret, "The secret should not be empty")

        # use the secret, we didn't scan the qr-code in tests
        totp = pyotp.TOTP(secret)
        browser.getControl(name="form.widgets.token").value = totp.now()
        browser.getControl(name="form.buttons.verify").click()

        self.assertIn("Welcome! You are now logged in", browser.contents)

    def test_tfaddform_login_process_with_expired_token(self):
        import pyotp
        import time

        member = self._getMember(TEST_USER_NAME)

        secret = member.getProperty("two_factor_authentication_secret")

        # the secret is empty
        self.assertFalse(secret, "The secret should be empty")

        browser = self._anon_browser()
        browser.open(f"{self.portal.absolute_url()}/login")
        browser.getControl(name="__ac_name").value = TEST_USER_NAME
        browser.getControl(name="__ac_password").value = TEST_USER_PASSWORD
        browser.getControl(name="buttons.login").click()

        member = self._getMember(TEST_USER_NAME)
        secret = member.getProperty("two_factor_authentication_secret")

        # the secret is not empty
        self.assertTrue(secret, "The secret should not be empty")

        # use the secret, we didn't scan the qr-code in tests
        totp = pyotp.TOTP(secret)

        # first we wait a little bit, until the token is invalid and then we click verify
        token = totp.now()
        browser.getControl(name="form.widgets.token").value = token

        # wait with the click
        time.sleep(40)
        browser.getControl(name="form.buttons.verify").click()

        self.assertIn("Invalid token or token expired", browser.contents)

    def test_tfaddform_login_process_with_invalid_token(self):

        browser = self._anon_browser()
        browser.open(f"{self.portal.absolute_url()}/login")
        browser.getControl(name="__ac_name").value = TEST_USER_NAME
        browser.getControl(name="__ac_password").value = TEST_USER_PASSWORD
        browser.getControl(name="buttons.login").click()

        # we guess the token
        token = "00195300"
        browser.getControl(name="form.widgets.token").value = token
        browser.getControl(name="form.buttons.verify").click()

        self.assertIn("Invalid token or token expired", browser.contents)
