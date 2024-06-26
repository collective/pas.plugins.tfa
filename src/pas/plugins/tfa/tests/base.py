from pas.plugins.tfa.testing import PAS_PLUGINS_OTP_FUNCTIONAL_TESTING
from plone.app.testing import SITE_OWNER_NAME
from plone.app.testing import SITE_OWNER_PASSWORD
from plone.testing.zope import Browser
from urllib.parse import parse_qs
from urllib.parse import urlparse

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

    def _extract_secret(self, otpauth_scheme):
        # otpauth://totp/test_user_1_@localhost?secret=F3ZHV2AGZCKQLBNH7FCGU2FAVYV2LGIM
        parse_result = urlparse(otpauth_scheme)
        result = parse_qs(parse_result.query)
        secret = result.get("secret")[0]
        return secret

    def _getMemberProperties(self, username):
        portal = self.layer["portal"]
        portal_memberdata = portal.portal_memberdata
        properties = portal_memberdata.propertyIds()
        member = self._getMember(username)
        member_properties = {}
        for prop in properties:
            member_properties.update({prop: member.getProperty(prop)})
        return member_properties
