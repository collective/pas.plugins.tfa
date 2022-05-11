import base64
import hashlib
import time
from urllib.parse import unquote

from plone import api
from plone.keyring.interfaces import IKeyManager
from Products.statusmessages.interfaces import IStatusMessage
import pyotp
# from ska import sign_url
# from ska import validate_signed_request_data
from zope.component import getUtility
from zope.globalrequest import getRequest
from zope.i18n import translate

try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

from . import _
from . import logger

SIGNATURE_LIFETIME = 600


def filter_data(url=None, data={}, exclude_args=["signature", "auth_user", "valid_until", "next_url"]):
    if url:
        url_qs = url.split("?")[1] if '?' in url else url
        data = [
            (k, v)
            for (k, v) in sorted(urlparse.parse_qsl(url_qs))
            if k not in exclude_args
        ]
    else:
        data = [
            (k, v)
            for (k, v) in sorted(data.items())
            if k not in exclude_args
        ]
    return "&".join(["{}={}".format(k, v) for (k, v) in data])


def sign_data(data_str, secret_key, auth_user, valid_until):
    signature = hashlib.sha256(
        "{}#{}#{}#{}".format(data_str, secret_key, auth_user, valid_until).encode()
    ).hexdigest()
    return signature

def sign_url(auth_user, secret_key, lifetime=SIGNATURE_LIFETIME, url= ""):
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
    data_str = filter_data(url=url)
    # import pdb; pdb.set_trace()
    signature = sign_data(data_str, secret_key, auth_user, valid_until)
    logger.info("S Signature: %s %s %s %s => %s", data_str, secret_key, auth_user, valid_until, signature)

    signed_url = "{url}{sep}auth_user={auth_user}&valid_until={valid_until}&signature={signature}".format(
        url=url,
        sep="?" if "?" not in url else "&",
        auth_user=auth_user,
        valid_until=valid_until,
        signature=signature,
    )
    logger.info("Signed URL: %s %s %s %s => %s", auth_user, secret_key, lifetime, url, signed_url)
    return signed_url


class ValidationResult(object):
    def __init__(self, result, reason=""):
        self.result = result
        self.reason = reason


def validate_signed_request_data(data={}, secret_key=None):
    """_summary_

    Args:
        data (dict, optional): _description_. Defaults to {}.
        secret_key (_type_, optional): _description_. Defaults to None.

    Returns:
        _type_: _description_
    """
    auth_user = data["auth_user"]
    valid_until = data["valid_until"]
    # TODO: mettere in reason l'eventuale tipo di errore (expire, invalid, ...)
    reason = []
    # TODO: verificare expired date
    data_str = filter_data(data=data)
    signature = sign_data(data_str, secret_key, auth_user, valid_until)
    logger.info("V Signature: %s %s %s %s => %s", data_str, secret_key, auth_user, valid_until, signature)
    return ValidationResult(result=signature == data["signature"], reason=reason)


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
    # TODO: Return hashed version if ``hashed`` is set to True.
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
    Signs the user data with `ska` package. The secret key is `secret_key` to
    be used with `ska` is a combination of:

    - Value of the ``two_factor_authentication_secret`` (from users' profile).
    - Browser info (hash of)
    - The SECRET set for the `ska` (use `plone.app.registry`).

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

    secret_key = get_ska_secret_key(request=request, user_secret=user_secret)
    signed_url = sign_url(auth_user=user.getUserId(), secret_key=secret_key, url=url)
    return signed_url


def get_ska_secret_key(
    request=None, user_secret=None, user=None, use_browser_hash=True
):
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

    # settings = get_app_settings()
    # ska_secret_key = settings.ska_secret_key
    # if use_browser_hash:
    #     browser_hash = get_browser_hash(request=request)
    # else:
    #     browser_hash = ''
    # return "{0}{1}{2}".format(user_secret, browser_hash, ska_secret_key)

    manager = getUtility(IKeyManager)
    ska_secret_key = manager.secret()
    return "{}{}".format(user_secret, ska_secret_key)


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


def validate_user_data(request, user, use_browser_hash=True):
    """
    Validates the user data.

    :param ZPublisher.HTTPRequest request:
    :param Products.PlonePAS.tools.memberdata user:
    :return ska.SignatureValidationResult:
    """
    secret_key = get_ska_secret_key(
        request=request, user=user, use_browser_hash=use_browser_hash
    )
    logger.info("validate_user_data: %s, %s", extract_request_data(request), secret_key)
    validation_result = validate_signed_request_data(
        data=extract_request_data(request), secret_key=secret_key
    )
    return validation_result


def extract_request_data_from_query_string(request_qs):
    """
    Plone seems to strip/escape some special chars (such as '+') from values
    and those chars are quite important for us. This method extracts the vars
    from request QUERY_STRING given and returns them unescaped.

    :FIXME: As stated above, for some reason Plone escapes from special chars
    from the values. If you know what the reason is and if it has some effects
    on security, please make the changes necessary.

    :param string request_qs:
    :return dict:
    """
    request_data = {}

    if not request_qs:
        return request_data

    for part in request_qs.split("&"):
        try:
            key, value = part.split("=", 1)
            request_data.update({key: unquote(value)})
        except ValueError:
            pass

    return request_data


def extract_request_data(request):
    """
    Plone seems to strip/escape some special chars (such as '+') from values
    and those chars are quite important for us. This method extracts the vars
    from request QUERY_STRING given and returns them unescaped.

    :FIXME: As stated above, for some reason Plone escapes from special chars
    from the values. If you know what the reason is and if it has some effects
    on security, please make the changes necessary.

    :param request ZPublisher.HTTPRequest:
    :return dict:
    """
    request_qs = request.get("QUERY_STRING")
    return extract_request_data_from_query_string(request_qs)


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
