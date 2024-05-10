from pas.plugins.tfa.testing import PAS_PLUGINS_OTP_FUNCTIONAL_TESTING
from plone.app.testing import SITE_OWNER_NAME
from plone.app.testing import SITE_OWNER_PASSWORD
from plone.testing.zope import Browser

import transaction
import unittest


class FunctionalBase(unittest.TestCase):

    layer = PAS_PLUGINS_OTP_FUNCTIONAL_TESTING

    def _anon_browser(self):
        transaction.commit()
        # Set up browser
        browser = Browser(self.layer["app"])
        browser.handleErrors = False
        return browser

    def _manager_browser(self):
        transaction.commit()
        # Set up browser
        browser = Browser(self.layer["app"])
        browser.handleErrors = False
        browser.addHeader(
            "Authorization",
            "Basic {}:{}".format(
                SITE_OWNER_NAME,
                SITE_OWNER_PASSWORD,
            ),
        )
        return browser

    def _getMember(self, username):

        # that's the plone user
        user = self.portal.acl_users.getUser(username)

        # that's the memberdata object
        member = self.portal.portal_membership.getMemberById(user.getId())

        return member
