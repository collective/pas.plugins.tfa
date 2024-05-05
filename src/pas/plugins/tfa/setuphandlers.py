from . import logger
from .plugins import TFAPlugin
from Products.CMFCore.utils import getToolByName
from Products.CMFPlone.interfaces import INonInstallable
from zope.interface import implementer


PLUGIN_ID = "two-factor-authentication"


@implementer(INonInstallable)
class HiddenProfiles:
    def getNonInstallableProfiles(self):
        """Hide uninstall profile from site-creation and quickinstaller."""
        return [
            "pas.plugins.tfa:uninstall",
        ]

    def getNonInstallableProducts(self):
        """Hide the upgrades package from site-creation and quickinstaller."""
        return ["pas.plugins.tfa.upgrades"]


def post_install(context):
    """Post install script"""
    # Do something at the end of the installation of this package.
    pas = getToolByName(context, "acl_users")

    # Create plugin if it does not exist.
    if PLUGIN_ID not in pas.objectIds():
        plugin = TFAPlugin(
            PLUGIN_ID,
            title="Two Factor Authentication",
        )
        pas._setObject(PLUGIN_ID, plugin)
        logger.info("Created %s in acl_users.", PLUGIN_ID)
    plugin = getattr(pas, PLUGIN_ID)
    if not isinstance(plugin, TFAPlugin):
        raise ValueError(f"Existing PAS plugin {PLUGIN_ID} is not a TFAPlugin.")

    # Activate all supported interfaces for this plugin.
    activate = []
    plugins = pas.plugins
    for info in plugins.listPluginTypeInfo():
        interface = info["interface"]
        interface_name = info["id"]
        if plugin.testImplements(interface):
            activate.append(interface_name)
            logger.info(
                "Activating interface %s for plugin %s", interface_name, info["title"]
            )

    plugin.manage_activateInterfaces(activate)
    logger.info("Plugins activated.")

    # Order some plugins to make sure our plugin is at the top.
    # This is not needed for all plugin interfaces.
    for info in plugins.listPluginTypeInfo():
        interface_name = info["id"]
        if interface_name in ["IAuthenticationPlugin", "IExtractionPlugin"]:
            iface = plugins._getInterfaceFromName(interface_name)
            for obj in plugins.listPlugins(iface):
                plugins.movePluginsUp(iface, [PLUGIN_ID])
            logger.info("Moved %s to top of %s.", PLUGIN_ID, interface_name)


def uninstall(context):
    """Uninstall script"""
    pas = getToolByName(context, "acl_users")
    if PLUGIN_ID not in pas.objectIds():
        return

    plugin = getattr(pas, PLUGIN_ID)
    if not isinstance(plugin, TFAPlugin):
        logger.warning("PAS plugin %s not removed: it is not a TFAPlugin.", PLUGIN_ID)
        return
    pas._delObject(PLUGIN_ID)
    logger.info("Removed TFAPlugin %s from acl_users.", PLUGIN_ID)
