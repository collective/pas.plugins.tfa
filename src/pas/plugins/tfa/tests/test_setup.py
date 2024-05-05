"""Setup tests for this package."""

from pas.plugins.tfa.testing import PAS_PLUGINS_OTP_INTEGRATION_TESTING  # noqa: E501
from plone import api
from plone.app.testing import setRoles
from plone.app.testing import TEST_USER_ID

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

    def test_product_installed(self):
        """Test if pas.plugins.tfa is installed."""
        if hasattr(self.installer, "is_product_installed"):
            installed = self.installer.is_product_installed("pas.plugins.tfa")
        else:
            installed = self.installer.isProductInstalled("pas.plugins.tfa")
        self.assertTrue(installed)

    def test_plugin_added(self):
        """Test if the plugin is added to acl_users."""
        from pas.plugins.tfa.plugins import TFAPlugin
        from pas.plugins.tfa.setuphandlers import PLUGIN_ID

        pas = api.portal.get_tool("acl_users")
        self.assertIn(PLUGIN_ID, pas.objectIds())
        plugin = getattr(pas, PLUGIN_ID)
        self.assertIsInstance(plugin, TFAPlugin)

    def test_browserlayer(self):
        """Test that IPasPluginsOtpLayer is registered."""
        from pas.plugins.tfa.interfaces import IPasPluginsOtpLayer
        from plone.browserlayer import utils

        self.assertIn(IPasPluginsOtpLayer, utils.registered_layers())


class TestUninstall(unittest.TestCase):
    layer = PAS_PLUGINS_OTP_INTEGRATION_TESTING

    def setUp(self):
        self.portal = self.layer["portal"]
        if get_installer:
            self.installer = get_installer(self.portal, self.layer["request"])
        else:
            self.installer = api.portal.get_tool("portal_quickinstaller")
        roles_before = api.user.get_roles(TEST_USER_ID)
        setRoles(self.portal, TEST_USER_ID, ["Manager"])
        if hasattr(self.installer, "uninstall_product"):
            self.installer.uninstall_product("pas.plugins.tfa")
        else:
            self.installer.uninstallProducts(["pas.plugins.tfa"])
        setRoles(self.portal, TEST_USER_ID, roles_before)

    def test_product_uninstalled(self):
        """Test if pas.plugins.tfa is cleanly uninstalled."""
        if hasattr(self.installer, "is_product_installed"):
            installed = self.installer.is_product_installed("pas.plugins.tfa")
        else:
            installed = self.installer.isProductInstalled("pas.plugins.tfa")
        self.assertFalse(installed)

    def test_browserlayer_removed(self):
        """Test that IPasPluginsOtpLayer is removed."""
        from pas.plugins.tfa.interfaces import IPasPluginsOtpLayer
        from plone.browserlayer import utils

        self.assertNotIn(IPasPluginsOtpLayer, utils.registered_layers())
