# -*- coding: utf-8 -*-
"""Setup tests for this package."""
from plone import api
from pas.plugins.tfa.testing import PAS_PLUGINS_OTP_INTEGRATION_TESTING  # noqa: E501
from pas.plugins.tfa import helpers

import unittest


try:
    # Plone 5.1+
    from Products.CMFPlone.utils import get_installer
except ImportError:
    # Plone 5.0/4.3
    def get_installer(context, request=None):
        return api.portal.get_tool("portal_quickinstaller")


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
        auth_user = "user1"
        secret_key = "secret"
        signed_url = helpers.sign_url(auth_user, secret_key, lifetime=10, url="")
        self.assertTrue(signed_url.startswith("?auth_user=user1&"))
