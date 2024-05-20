from pas.plugins.tfa.testing import PAS_PLUGINS_OTP_INTEGRATION_TESTING  # noqa: E501
from plone.app.testing import setRoles
from plone.app.testing import TEST_USER_ID

import unittest


QR_CODE_REF = "iVBORw0KGgoAAAANSUhEUgAAAZoAAAGaAQAAAAAefbjOAAADGElEQVR4nO2bS46bQBCGvwpIXjY3mKPAzUY5Um4AR/EBIsHSEujPorqBmckmcYI9Q7FAfn1ytyjV469qE398Dd/+nIGAAgoooIACCuhrQpavGusms/zdVJdfTeUH3UOWF9DxUCtJGkE9ldw2rIFiFpUkSW+h45YX0PHQlB2AdSzmtqFxMbOXm7sMM6vfQ8ctL6CHQfreZLOwjkpAJev+xz8F9EmgVjMMDTA0i30E/t0/BfTUUJLUA2Z2ESSJdqxEO4J6QNL8uOUFdDQ0mJmnku0ItNetzKixjsVLjUctL6DjIH/ym5QtyKmkYPYbpLda95PvKaB7ILyqbMdqV316hGg1u8uQNCONlbxK7Z98TwHdD+l7s5jZiwTpZtZNNTBdBGnOucXwEnnEGaB6/2aqZ7eDXGtgGgw0dIsBdTGJJ99TQPdAHjVy6JCUo8a43QCovP7wK6LGV4ZyHkGagWIMuAkAJcGotLvCIr4ytGaWoD6tmQJV1iMANlEiMsuvD+Wo0VOpPHMvN4tMpRn1JWCERZwHSjez1yJgq2cx2qsZTBfZ69XMbBO1P8meAvobaM0s5yxW9yk7hdwhL9r15ijCR5wBGho8ScgqBIvlTtdUF2V7BOses7yAjobs9VoDkxmkm2WlclxNgJiPOA20Vp8qisO4lqBp3tWmu0gSUeMEUDsuRnstfc6OXG762GV7vXgd6uXIJ9lTQHdllsUp7KXJlGcvs0wV1eeJILMGpG0qgsX85v2tdCtj2A9ZXkCPqj5X97AlE5tcSeQRp4BK7gg+AVHMIs9HaDdLl+ZQsU8A7Xqfu6pjMwaXIkoKERZxFmg70+WixGA1DFb7SFU+xjPFnOUZoNL7fJM9bEMSOx8R8xHngHbdcC8y+zSzNcLLxAxE1DgtNNUfPvIOOdH7PAP0/vEbVDNMAOlnbe2PamZoRhlTc/zyAjocKhaRBEwgdwXpZrQ/LjJYjHZcag0v66GNJ99TQPdA2SIGDwgV1vb+SvhZniQMKhmJ8u2T7ymge6DfnOmq1nclvXx7e/o9BRRQQAEFFFBAx0C/ADwlZbk/JKCmAAAAAElFTkSuQmCC"


class TestIntegrationHelpers(unittest.TestCase):
    """Test that pas.plugins.tfa is properly installed."""

    layer = PAS_PLUGINS_OTP_INTEGRATION_TESTING

    def setUp(self):
        """Custom shared utility setup for tests."""
        self.portal = self.layer["portal"]
        self.request = self.layer["request"]
        setRoles(self.portal, TEST_USER_ID, ["Member"])
        self.portal.acl_users.userFolderAddUser("user1", "secret", ["Member"], [])

    def test_sign_url(self):

        from pas.plugins.tfa.helpers import sign_url

        login = "user1"
        secret_key = "secret"
        signed_url = sign_url(login, secret_key, lifetime=10, url="")
        self.assertTrue(signed_url.startswith("?login=user1&"))

        signed_url = sign_url(login, secret_key, lifetime=None, url="")
        self.assertTrue(signed_url.startswith("?login=user1&"))

    def test_sign_data(self):
        from pas.plugins.tfa.helpers import sign_data

        import hashlib

        signature1 = sign_data(
            secret_key="tmp-123",
            name="john doe",
        )

        signature2 = hashlib.sha256(b"name=john doe&secret_key=tmp-123").hexdigest()

        signature3 = sign_data(
            name="john doe",
        )

        signature4 = hashlib.sha256(b"name=john doe").hexdigest()

        self.assertEqual(signature1, signature2)
        self.assertEqual(signature3, signature4)

    def test_sign_user_data(self):

        from pas.plugins.tfa.helpers import sign_user_data

        url = sign_user_data(request=None, user=None)
        self.assertIn("@@tfa", url)
        self.assertIn(TEST_USER_ID, url)

    def test_extract_ip_address_from_request(self):
        from pas.plugins.tfa.helpers import extract_ip_address_from_request

        # inject a IP
        remote_ip = "10.10.10.11"
        self.request.environ.update({"REMOTE_ADDR": remote_ip})

        # extract with request as parameter
        ip = extract_ip_address_from_request(self.request)
        self.assertEqual(ip, remote_ip)

        # extract without request as parameter
        ip = extract_ip_address_from_request()
        self.assertEqual(ip, remote_ip)

        # inject a proxy IP
        proxy_ips = "10.10.10.9, 10.10.10.10"
        self.request.environ.update({"HTTP_X_FORWARDED_FOR": proxy_ips})
        ip = extract_ip_address_from_request(self.request)
        self.assertEqual(ip, "10.10.10.9")

    def test_get_domain_name(self):
        from pas.plugins.tfa.helpers import get_domain_name

        domain = get_domain_name(self.request)
        self.assertEqual(domain, "nohost")

    def test_qr_code_generation(self):
        from pas.plugins.tfa.helpers import get_barcode_image

        # that's the plone user
        testuser = self.portal.acl_users.getUser("user1")

        # that's the memberdata object
        # member = self.portal.portal_membership.getMemberById(testuser.getId())

        # use a dummy domain
        domain = "dummy-host.local"

        # use a dummy secret
        secret = "12345"

        base64_image = get_barcode_image(
            testuser.getId(),
            domain,
            secret,
        )
        self.assertEqual(str(base64_image), QR_CODE_REF)

    def test_get_or_create_secret(self):
        from pas.plugins.tfa.helpers import get_or_create_secret

        secret = get_or_create_secret()

        self.assertIsNotNone(secret)

    def test_get_or_create_secret_override(self):
        from pas.plugins.tfa.helpers import get_or_create_secret

        secret = get_or_create_secret(overwrite=True)

        self.assertIsNotNone(secret)

    def test_get_secret_key(self):
        from pas.plugins.tfa.helpers import get_secret_key

        key = get_secret_key()
        self.assertIsNotNone(key)

    def test_get_secret_key_temp(self):
        from pas.plugins.tfa.helpers import get_secret_key

        # that's the memberdata object
        member = self.portal.portal_membership.getMemberById("user1")
        # fake temp secret
        fake_secret = "1953"
        member.setMemberProperties(
            mapping={"two_factor_authentication_secret": f"temp-{fake_secret}"}
        )
        secret_key = get_secret_key(user=member)
        self.assertTrue(secret_key.startswith(fake_secret))

    def test_validate_token(self):
        from pas.plugins.tfa.helpers import validate_token

        # no user as parameter and an invalid token
        result = validate_token(123)
        self.assertFalse(result)
