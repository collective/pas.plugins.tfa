# -*- coding: utf-8 -*-
from plone.app.contenttypes.testing import PLONE_APP_CONTENTTYPES_FIXTURE
from plone.app.robotframework.testing import REMOTE_LIBRARY_BUNDLE_FIXTURE
from plone.app.testing import (
    applyProfile,
    FunctionalTesting,
    IntegrationTesting,
    PloneSandboxLayer,
)
from plone.testing import z2

import pas.plugins.tfa


class PasPluginsOtpLayer(PloneSandboxLayer):

    defaultBases = (PLONE_APP_CONTENTTYPES_FIXTURE,)

    def setUpZope(self, app, configurationContext):
        # Load any other ZCML that is required for your tests.
        # The z3c.autoinclude feature is disabled in the Plone fixture base
        # layer.

        self.loadZCML(package=pas.plugins.tfa)

    def setUpPloneSite(self, portal):
        applyProfile(portal, "pas.plugins.tfa:default")


PAS_PLUGINS_OTP_FIXTURE = PasPluginsOtpLayer()


PAS_PLUGINS_OTP_INTEGRATION_TESTING = IntegrationTesting(
    bases=(PAS_PLUGINS_OTP_FIXTURE,),
    name="PasPluginsOtpLayer:IntegrationTesting",
)


PAS_PLUGINS_OTP_FUNCTIONAL_TESTING = FunctionalTesting(
    bases=(PAS_PLUGINS_OTP_FIXTURE,),
    name="PasPluginsOtpLayer:FunctionalTesting",
)


PAS_PLUGINS_OTP_ACCEPTANCE_TESTING = FunctionalTesting(
    bases=(
        PAS_PLUGINS_OTP_FIXTURE,
        REMOTE_LIBRARY_BUNDLE_FIXTURE,
        z2.ZSERVER_FIXTURE,
    ),
    name="PasPluginsOtpLayer:AcceptanceTesting",
)
