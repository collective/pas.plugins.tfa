# -*- coding: utf-8 -*-
import hashlib
import time

from plone import api
from plone.keyring.interfaces import IKeyManager
from Products.statusmessages.interfaces import IStatusMessage
import pyotp
from zope.component import getUtility
from zope.globalrequest import getRequest
from zope.i18n import translate

# try:
#     import urllib.parse as urlparse
# except ImportError:
#     import urlparse

from . import logger

SIGNATURE_LIFETIME = 600


# def filter_data(
#     url, exclude_args=["signature", "auth_user", "valid_until", "next_url"]
# ):
#     """_summary_
#
#     Args:
#         url (str): _description_
#         exclude_args (list, optional): _description_. Defaults to ["signature", "auth_user", "valid_until", "next_url"].
#
#     Returns:
#         str: _description_
#     """
#     url_qs = url.split("?")[1] if "?" in url else url
#     data = [
#         (k, v) for (k, v) in sorted(urlparse.parse_qsl(url_qs)) if k not in exclude_args
#     ]
#     return "&".join(["{}={}".format(k, v) for (k, v) in data])


def sign_data(**kwargs):
    signature = hashlib.sha256(
        "&".join("{}={}".format(k, v) for k, v in sorted(kwargs.items())).encode()
    ).hexdigest()
    return signature


def sign_url(auth_user, secret_key, lifetime=SIGNATURE_LIFETIME, url=""):
    """Sign the URL.
    :param auth_user: Username of the user making the request.
    :param secret_key: The shared secret key.
    :param lifetime: Signature lifetime in seconds.
    :param url: URL to be signed.
    """
    if lifetime is None:
        lifetime = SIGNATURE_LIFETIME

    assert isinstance(lifetime, int)

    valid_until = int(time.time()) + lifetime
    signature = sign_data(
        secret_key=secret_key, auth_user=auth_user, valid_until=valid_until
    )
    logger.debug(
        "S Signature: %s %s %s => %s",
        secret_key,
        auth_user,
        valid_until,
        signature,
    )

    signed_url = "{url}{sep}auth_user={auth_user}&valid_until={valid_until}&signature={signature}".format(
        url=url,
        sep="?" if "?" not in url else "&",
        auth_user=auth_user,
        valid_until=valid_until,
        signature=signature,
    )
    logger.debug(
        "Signed URL: %s %s %s %s => %s",
        auth_user,
        secret_key,
        lifetime,
        url,
        signed_url,
    )
    return signed_url


def get_or_create_secret(user=None, overwrite=False):
    """
    Gets or creates token secret for the user given. Checks first if user
    given has a ``secret`` generated.
    If not, generate it for him and save it in his profile
    (``two_factor_authentication_secret``).

    :param Products.PlonePAS.tools.memberdata user: If provided, used.
        Otherwise ``plone.api.user.get_current`` is used to obtain the user.
    :return string:
    """
    if user is None:
        user = api.user.get_current()
    if not overwrite:
        secret = user.getProperty("two_factor_authentication_secret", None)
        if isinstance(secret, str) and secret:
            return secret
    secret = pyotp.random_base32()
    # TODO p.protect.safeWrite ?
    user.setMemberProperties(mapping={"two_factor_authentication_secret": secret})
    return secret


def sign_user_data(request=None, user=None, url="@@2fa-login"):
    """
    Signs the user data.

    :param ZPublisher.HTTPRequest request:
    :param Products.PlonePAS.tools.memberdata user:
    :param string url:
    :return string:
    """
    if request is None:
        request = getRequest()

    if user is None:
        user = api.user.get_current()

    # Make sure the secret key always exists
    user_secret = get_or_create_secret(user)
    secret_key = get_secret_key(request=request, user_secret=user_secret)
    signed_url = sign_url(auth_user=user.getUserId(), secret_key=secret_key, url=url)
    return signed_url


def get_secret_key(request=None, user_secret=None, user=None):
    """
    Gets the `secret_key` to be used in `ska` package.

    - Value of the ``two_factor_authentication_secret`` (from users' profile).
    - Browser info (hash of)
    - The SECRET set for the `ska` (use `plone.app.registry`).

    :param ZPublisher.HTTPRequest request:
    :param Products.PlonePAS.tools.memberdata user:
    :param bool use_browser_hash: If set to True, browser hash is used.
        Otherwise - not. Defaults to True.
    :return string:
    """
    if request is None:
        request = getRequest()

    if user_secret is None:
        if user is None:
            user = api.user.get_current()
        user_secret = user.getProperty("two_factor_authentication_secret")
    manager = getUtility(IKeyManager)
    system_secret_key = manager.secret()
    return "{}{}".format(user_secret, system_secret_key)


def drop_login_failed_msg(request):
    """
    Drop an eventual "Login failed..." status message from the request,
    but keep all other messages by re-adding them.

    Because what ends up in the request is the message translated in the
    user's language, we have to first translate the "Login failed" message
    using the same request(i.e. language), and then filter out the status
    message based on that.

    :param ZPublisher.HTTPRequest request:
    """
    login_failed = (
        "Login failed. Both login name and password are case "
        "sensitive, check that caps lock is not enabled."
    )
    login_failed_translated = translate(login_failed, domain="plone", context=request)
    status_messages = IStatusMessage(request)
    msgs = status_messages.show()
    for msg in msgs:
        if msg.message == login_failed_translated:
            # Drop the "Login failed" message
            continue
        status_messages.add(msg.message, msg.type)


class SignatureValidationResult(object):
    def __init__(self, result, reason=""):
        self.result = result
        self.reason = reason


def validate_user_data(request, user):
    """
    Validates the user data.

    :param ZPublisher.HTTPRequest request:
    :param Products.PlonePAS.tools.memberdata user:
    :return SignatureValidationResult:
    """
    secret_key = get_secret_key(request=request, user=user)
    auth_user = request.get("auth_user")
    valid_until = int(request.get("valid_until"))
    reason = []
    if valid_until < int(time.time()):
        reason.append("token expired")
        result = False
    else:
        signature = sign_data(
            secret_key=secret_key, auth_user=auth_user, valid_until=valid_until
        )
        logger.debug(
            "V Signature: %s %s %s => %s",
            secret_key,
            auth_user,
            valid_until,
            signature,
        )
        if signature == request.get("signature"):
            result = True
        else:
            reason.append("invalid signature")
            result = False
    return SignatureValidationResult(result=result, reason=reason)


# def extract_request_data_from_query_string(request_qs):
#     """
#     Plone seems to strip/escape some special chars (such as '+') from values
#     and those chars are quite important for us. This method extracts the vars
#     from request QUERY_STRING given and returns them unescaped.
#
#     :FIXME: As stated above, for some reason Plone escapes from special chars
#     from the values. If you know what the reason is and if it has some effects
#     on security, please make the changes necessary.
#
#     :param string request_qs:
#     :return dict:
#     """
#     request_data = {}
#     if not request_qs:
#         return request_data
#     for part in request_qs.split("&"):
#         try:
#             key, value = part.split("=", 1)
#             request_data.update({key: urlparse.unquote(value)})
#         except ValueError:
#             pass
#     return request_data


# def extract_request_data(request):
#     """
#     Plone seems to strip/escape some special chars (such as '+') from values
#     and those chars are quite important for us. This method extracts the vars
#     from request QUERY_STRING given and returns them unescaped.
#
#     :FIXME: As stated above, for some reason Plone escapes from special chars
#     from the values. If you know what the reason is and if it has some effects
#     on security, please make the changes necessary.
#
#     :param request ZPublisher.HTTPRequest:
#     :return dict:
#     """
#     request_qs = request.get("QUERY_STRING")
#     return extract_request_data_from_query_string(request_qs)


def validate_token(token, user=None):
    """
    Validates the given token.

    :param string token:
    :return bool:
    """
    if user is None:
        user = api.user.get_current()
    user_secret = user.getProperty("two_factor_authentication_secret")
    # TODO: il token va validato secondo l'algoritmo definito dal 'device' impostato
    # per l'user
    # per gli SMS mettiamo 10 minuti di validità, si potrebbe eventualmente anche pensare
    # di usare HOTP al posto di TOTP
    validation_result = pyotp.TOTP(user_secret, interval=10 * 60).verify(token)
    logger.info(
        "validate_token: token: %s %s %s", user_secret, token, validation_result
    )
    return validation_result


def extract_ip_address_from_request(request=None):
    """
    Extracts client's IP address from request. This is not the safest solution,
    since client may change headers. The first endpoint must remove a possibly forged
    X-Forwarded-For header

    :param ZPublisher.HTTPRequest request:
    :return string:
    """
    if not request:
        request = getRequest()
    ip = request.get("REMOTE_ADDR")
    x_forwarded_for = request.get("HTTP_X_FORWARDED_FOR")

    if x_forwarded_for:
        proxies = [proxy.strip() for proxy in x_forwarded_for.split(",")]
        ip = proxies[0]
    return ip
    # return ipaddress.ip_address(ip)
