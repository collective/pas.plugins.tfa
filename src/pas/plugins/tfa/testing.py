from plone.app.robotframework.testing import REMOTE_LIBRARY_BUNDLE_FIXTURE
from plone.app.testing import applyProfile
from plone.app.testing import FunctionalTesting
from plone.app.testing import IntegrationTesting
from plone.app.testing import PLONE_FIXTURE
from plone.app.testing import PloneSandboxLayer
from plone.testing.zope import WSGI_SERVER_FIXTURE


class PasPluginsOtpLayer(PloneSandboxLayer):
    defaultBases = (PLONE_FIXTURE,)

    def setUpZope(self, app, configurationContext):
        # Load any other ZCML that is required for your tests.
        # The z3c.autoinclude feature is disabled in the Plone fixture base
        # layer.

        import pas.plugins.tfa
        import plone.restapi

        self.loadZCML(package=pas.plugins.tfa)
        self.loadZCML(package=plone.restapi)

    def setUpPloneSite(self, portal):
        applyProfile(portal, "plone.restapi:default")
        applyProfile(portal, "pas.plugins.tfa:default")


PAS_PLUGINS_OTP_FIXTURE = PasPluginsOtpLayer()


PAS_PLUGINS_OTP_INTEGRATION_TESTING = IntegrationTesting(
    bases=(PAS_PLUGINS_OTP_FIXTURE,),
    name="PasPluginsOtpLayer:IntegrationTesting",
)


PAS_PLUGINS_OTP_FUNCTIONAL_TESTING = FunctionalTesting(
    bases=(PAS_PLUGINS_OTP_FIXTURE, WSGI_SERVER_FIXTURE),
    name="PasPluginsOtpLayer:FunctionalTesting",
)


PAS_PLUGINS_OTP_ACCEPTANCE_TESTING = FunctionalTesting(
    bases=(
        PAS_PLUGINS_OTP_FIXTURE,
        REMOTE_LIBRARY_BUNDLE_FIXTURE,
        WSGI_SERVER_FIXTURE,
    ),
    name="PasPluginsOtpLayer:AcceptanceTesting",
)
