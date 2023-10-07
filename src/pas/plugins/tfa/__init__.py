# -*- coding: utf-8 -*-
"""Init and utils."""
from AccessControl.Permissions import manage_users as ManageUsers
from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin
from zope.i18nmessageid import MessageFactory
import logging


try:
    from iw.rejectanonymous import addValidSubparts

    addValidSubparts("@@tfa")
except ImportError:
    pass

_ = MessageFactory("pas.plugins.tfa")
PMF = MessageFactory("plone")
logger = logging.getLogger(__name__)


def initialize(context):  # pragma: no cover
    """Initializer called when used as a Zope 2 product."""
    from pas.plugins.tfa import plugins

    registerMultiPlugin(plugins.TFAPlugin.meta_type)

    context.registerClass(
        plugins.TFAPlugin,
        permission=ManageUsers,
        constructors=(
            plugins.manage_addTwoFactorAutenticationPluginForm,
            plugins.addTwoFactorAutenticationAuthenticatorPlugin,
        ),
        # icon='www/PluggableAuthService.png',
    )
