"""Setup tests for this package."""

from pas.plugins.tfa import helpers
from pas.plugins.tfa.testing import PAS_PLUGINS_OTP_INTEGRATION_TESTING  # noqa: E501
from plone import api
from plone.base.utils import get_installer

import unittest


class TestSetup(unittest.TestCase):
    """Test that pas.plugins.tfa is properly installed."""

    layer = PAS_PLUGINS_OTP_INTEGRATION_TESTING

    def setUp(self):
        """Custom shared utility setup for tests."""
        self.portal = self.layer["portal"]
        if get_installer:
            self.installer = get_installer(self.portal, self.layer["request"])
        else:
            self.installer = api.portal.get_tool("portal_quickinstaller")

    def test_sign_url(self):
        login = "user1"
        secret_key = "secret"
        signed_url = helpers.sign_url(login, secret_key, lifetime=10, url="")
        self.assertTrue(signed_url.startswith("?login=user1&"))
