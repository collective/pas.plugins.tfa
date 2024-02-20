# -*- coding: utf-8 -*-
"""
The idea of this PAS plugin is quite simple. It should check the user profile
for the user being logged in and if user has enabled two-step verification for
his account (``two_factor_authentication_enabled`` is set to True), then
redirect him further to a another page, where he would enter his 2FA token,
after successful validation of which the user would be
definitely logged in.

If user has not enabled the two-step verification for his account
(``two_factor_authentication_enabled`` is set to False), then do nothing so
that Plone continues logging in the user normal way.
"""
from AccessControl.class_init import InitializeClass
from AccessControl.SecurityInfo import ClassSecurityInfo
from plone import api
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin
from Products.PluggableAuthService.interfaces.plugins import IExtractionPlugin
from Products.PluggableAuthService.PluggableAuthService import (
    _SWALLOWABLE_PLUGIN_EXCEPTIONS,
)
from Products.PluggableAuthService.PluggableAuthService import reraise
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from plone.restapi.pas.plugin import JWTAuthenticationPlugin
from . import logger

# from .helpers import extract_ip_address_from_request
from .helpers import get_or_create_secret
from .helpers import sign_user_data
from .helpers import get_domain_name
from .helpers import validate_token
from .interfaces import OTP_CHALLENGE_KEY
from zope.annotation.interfaces import IAnnotations
from plone.restapi.deserializer import json_body
from plone.restapi.exceptions import DeserializationError


manage_addTwoFactorAutenticationPluginForm = PageTemplateFile(
    "www/add_tfa_form", globals(), __name__="manage_addTwoFactorAutenticationPluginForm"
)


def addTwoFactorAutenticationAuthenticatorPlugin(self, id, title="", REQUEST=None):
    """
    Add a Two Factor Autentication PAS Plugin to Plone PAS
    """
    o = TFAPlugin(id, title)
    self._setObject(o.getId(), o)

    if REQUEST is not None:
        msg = "Two+Factor+Autentication+PAS+Plugin+added."
        REQUEST["RESPONSE"].redirect(
            "{0}/manage_main?manage_tabs_message={1}".format(self.absolute_url(), msg)
        )


class TFAPlugin(BasePlugin):
    """
    TFA PAS Plugin
    """

    meta_type = "Collective Two Factor Autentication PAS"
    security = ClassSecurityInfo()

    def __init__(self, id, title=None):
        self._setId(id)
        self.title = title

    # def is_whitelisted_client(self):
    #     # TODO: spostare nei registry o nelle properties del plugin
    #     settings = {
    #         "whitelist": ["10.0.", "10.1."],
    #     }
    #     ip = extract_ip_address_from_request(self.REQUEST)
    #     logger.debug("ip detected %s", ip)
    #     for prefix in settings["whitelist"]:
    #         if ip.startswith(prefix):
    #             return True
    #     return False

    def extractCredentials(self, request):
        try:
            creds = json_body(request)
        except DeserializationError:
            return {}
        if creds:
            if "otp" in creds and "login" in creds:
                return creds
        return {}

    def authenticateCredentials(self, credentials):
        """
        Place to actually validate the user credentials specified and return a
        tuple (login, login) on success or (None, None) on failure.

        If we find one and two-step verification is not enabled for the
        account, we consider the authentication passed and log the user in. If
        two-step verification has been enabled for the account, the first step
        of authentication is considered to be passed and we go to the next
        page (having the user and pass remembered), where we check for the
        token submitted. If the token is valid too, we log the user in.
        """
        login = credentials.get("login")
        if not login:
            return None

        # if self.is_whitelisted_client():
        #     return None

        user = api.user.get(username=login)
        logger.debug("Found user: %s", user)
        if not user:
            return None

        two_factor_authentication_enabled = user.getProperty(
            "two_factor_authentication_enabled", False
        )
        logger.debug(
            "Two-step verification enabled: {0}".format(
                two_factor_authentication_enabled
            )
        )

        if two_factor_authentication_enabled:
            # if "otp" in credentials:
            if credentials.get("extractor") == self.getId():
                if validate_token(credentials["otp"], user=user):
                    return (login, login)
                else:
                    # invalid token
                    return None

            # First see, if the password is correct.
            # We do this by allowing all IAuthenticationPlugin plugins to
            # authenticate the credentials, and pick the first one that is
            # successful.
            pas_plugins = self._getPAS().plugins
            auth_plugins = pas_plugins.listPlugins(IAuthenticationPlugin)
            authorized = None
            for plugid, authplugin in auth_plugins:
                logger.debug("auth_plugin: %s %s ", plugid, authplugin)
                if plugid == self.getId():
                    # Avoid infinite recursion
                    continue
                if (
                    isinstance(authplugin, JWTAuthenticationPlugin)
                    and "token" not in credentials
                ):
                    continue

                # credentials.get("extractor")
                # TODO: if jwt extractor and token in credentials verify token

                try:
                    authorized = authplugin.authenticateCredentials(credentials)
                except _SWALLOWABLE_PLUGIN_EXCEPTIONS:
                    reraise(authplugin)
                    msg = "AuthenticationPlugin {0} error".format(plugid)
                    logger.warning(msg, exc_info=True)
                    continue

                if authorized is not None:
                    # An auth plugin successfully authenticated the user
                    break

            if authorized is None:
                # No auth plugin was able to authenticate the user
                return None

            # Consume the credentials after we verified the credentials above.
            # We need to do this to prevent later IAuthenticationPlugins
            # from authenticating the user before we verified the token.
            # This does produce a "Login failed" status message though that
            # we need to remove in the token validation view

            # TODO: se non è possibile creare/inviare il token l'autenticazione
            # deve fallire (si eliminano i dati in credentials) oppure deve
            # andare correttamente (si spostano queste due righe dentro l'if) ?

            request = self.REQUEST

            # TODO: if request is restapi @login
            # if request.getHeader("Accept") == "application/json":
            if credentials.get("extractor") == "jwt" and "token" in credentials:
                logger.debug("JWT extractor found %s", credentials)
                return

            credentials.clear()
            # for key in list(credentials.keys()):
            #     del credentials[key]

            if request.getHeader("Accept") == "application/json":
                # restapi / volto
                if not IAnnotations(request).get(OTP_CHALLENGE_KEY):
                    if user.getProperty(
                        "two_factor_authentication_secret", None
                    ) and not user.getProperty(
                        "two_factor_authentication_secret"
                    ).startswith(
                        "temp-"
                    ):
                        IAnnotations(request)[OTP_CHALLENGE_KEY] = {
                            # TODO: kind of otp method (sms, voicecall, app, ...)
                            "type": "totp",
                            "action": "challenge",
                            "login": user.getId(),
                            "signature": sign_user_data(
                                request=request, user=user, url=""
                            ),
                        }
                    else:
                        # TODO: instead of creating a temporary secret, send the signed secret in the response
                        # and verify it later (?)
                        # FIX: if I start to add a new secret, the old one is lost
                        secret = get_or_create_secret(user, prefix="temp-")
                        IAnnotations(request)[OTP_CHALLENGE_KEY] = {
                            "type": "totp",
                            "action": "add",
                            "login": user.getId(),
                            # TODO: urlencode user and domain
                            "qr_code": f"otpauth://totp/{user.getId()}@{get_domain_name()}?secret={secret}",
                            "signature": sign_user_data(
                                request=request, user=user, url=""
                            ),
                        }
            else:
                # Plone / CLassic UI
                # if self.create_and_deliver_token(user):
                response = request["RESPONSE"]
                if user.getProperty(
                    "two_factor_authentication_secret", None
                ) and not user.getProperty(
                    "two_factor_authentication_secret"
                ).startswith(
                    "temp-"
                ):
                    signed_url = sign_user_data(request=request, user=user, url="@@tfa")
                else:
                    # TODO: instead of creating a temporary secret, send the signed secret in the response
                    # and verify it later (?)
                    # FIX: if I start to add a new secret, the old one is lost
                    signed_url = sign_user_data(
                        request=request, user=user, url="@@tfa-add"
                    )
                came_from = request.get("came_from", "")
                if came_from:
                    signed_url = "{0}&next_url={1}".format(signed_url, came_from)

                # XXX: an error status message is needed if using the login popup,
                # otherwise it is automatically closed
                api.portal.show_message("TOKEN_REQUIRED", request, type="error")
                response.redirect(signed_url, lock=1)
                return None
        return None

    # def create_and_deliver_token(self, user):
    #     """_summary_

    #     Args:
    #         user (_type_): _description_
    #         token (_type_): _description_

    #     Raise:
    #         ....

    #     Returns:
    #         _type_: _description_
    #     """
    #     # TODO: creare e spedire il token via sms all'utente. usando un adapter
    #     # TODO: opzione a: si crea una form intermedia dove l'utente sceglie la modalità di
    #     # token preferita (sms, voicecall, app, ...), se di modalità disponibili ce n'è solo una
    #     # la pagian intermedia viene saltata
    #     # TODO: opzione b: la scelta dell'utente è salvata sul suo profilo
    #     user_secret = get_or_create_secret(user)
    #     logger.debug("User secret: %s", user_secret)
    #     # TODO: per gli SMS mettiamo 10 minuti di validità, si potrebbe eventualmente anche pensare
    #     # di usare HOTP al posto di TOTP
    #     # TODO: riportare in uno statusmessage l'informazione che il token è stato spedito
    #     # al numero di cellulare via sms indicando le ultime cifre del numero
    #     token = pyotp.TOTP(user_secret, interval=10 * 60).now()
    #     logger.debug("Deliver token: %s to user: %s", token, user)
    #     return True


classImplements(TFAPlugin, IAuthenticationPlugin, IExtractionPlugin)
InitializeClass(TFAPlugin)
