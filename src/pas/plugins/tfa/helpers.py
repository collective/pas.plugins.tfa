from . import logger
from io import BytesIO
from plone import api
from plone.keyring.interfaces import IKeyManager
from Products.statusmessages.interfaces import IStatusMessage
from urllib.parse import urlparse
from zope.component import getUtility
from zope.globalrequest import getRequest
from zope.i18n import translate

import base64
import hashlib
import pyotp
import qrcode
import time


SIGNATURE_LIFETIME = 600


def sign_data(**kwargs):
    if kwargs.get("secret_key"):
        kwargs["secret_key"] = kwargs["secret_key"].replace("temp-", "")
    signature = hashlib.sha256(
        "&".join(f"{k}={v}" for k, v in sorted(kwargs.items())).encode()
    ).hexdigest()
    return signature


def sign_url(login, secret_key, lifetime=SIGNATURE_LIFETIME, url=""):
    """Sign the URL.
    :param login: Username of the user making the request.
    :param secret_key: The shared secret key.
    :param lifetime: Signature lifetime in seconds.
    :param url: URL to be signed.
    """
    if lifetime is None:
        lifetime = SIGNATURE_LIFETIME

    assert isinstance(lifetime, int)

    valid_until = int(time.time()) + lifetime
    signature = sign_data(secret_key=secret_key, login=login, valid_until=valid_until)
    logger.debug(
        "S Signature: %s %s %s => %s",
        secret_key,
        login,
        valid_until,
        signature,
    )
    sep = "?" if "?" not in url else "&"
    signed_url = (
        f"{url}{sep}login={login}&valid_until={valid_until}&signature={signature}"
    )
    logger.debug(
        "Signed URL: %s %s %s %s => %s",
        login,
        secret_key,
        lifetime,
        url,
        signed_url,
    )
    return signed_url


def get_or_create_secret(user=None, overwrite=False, prefix=""):
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
            if secret.startswith(prefix):
                secret = secret[len(prefix) :]  # noqa
            return secret
    secret = pyotp.random_base32()
    user.setMemberProperties(
        mapping={"two_factor_authentication_secret": f"{prefix}{secret}"}
    )
    return secret


def sign_user_data(request=None, user=None, url="@@tfa"):
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
    signed_url = sign_url(login=user.getUserId(), secret_key=secret_key, url=url)
    return signed_url


def get_secret_key(request=None, user_secret=None, user=None):
    """
    Gets the `secret_key` to be used in `ska` package.

    - Value of the ``two_factor_authentication_secret`` (from users' profile).
    - Browser info (hash of)
    - The SECRET set for the `ska` (use `plone.app.registry`).

    :param ZPublisher.HTTPRequest request:
    :param string user_secret:
    :param Products.PlonePAS.tools.memberdata user:
    :return string:
    """
    if request is None:
        request = getRequest()

    if user_secret is None:
        if user is None:
            user = api.user.get_current()
        user_secret = user.getProperty("two_factor_authentication_secret")
        if user_secret and user_secret.startswith("temp-"):
            user_secret = user_secret[5:]
    manager = getUtility(IKeyManager)
    system_secret_key = manager.secret()
    return f"{user_secret}{system_secret_key}"


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


class SignatureValidationResult:
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
    user_secret = get_secret_key(request=request, user=user)
    if user_secret and user_secret.startswith("temp-"):
        user_secret = user_secret[5:]
        user_secret_temp = True
    else:
        user_secret_temp = False
    login = request.get("login")
    valid_until = int(request.get("valid_until"))
    reason = []
    if valid_until < int(time.time()):
        reason.append("token expired")
        result = False
    else:
        signature = sign_data(
            secret_key=user_secret, login=login, valid_until=valid_until
        )
        logger.debug(
            "V Signature: %s %s %s => %s",
            user_secret,
            login,
            valid_until,
            signature,
        )
        if signature == request.get("signature"):
            if user_secret_temp:
                user.setMemberProperties(
                    {"two_factor_authentication_secret": user_secret}
                )
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


def validate_token(token, user=None, user_secret=None, interval=30):
    """
    Validates the given token.

    :param string token:
    :return bool:
    """
    user_secret_temp = False
    if user_secret is None:
        if user is None:
            user = api.user.get_current()
        user_secret = user.getProperty("two_factor_authentication_secret")
        if user_secret and user_secret.startswith("temp-"):
            user_secret = user_secret[5:]
            user_secret_temp = True
        else:
            user_secret_temp = False

    # TODO: il token va validato secondo l'algoritmo definito dal 'device' impostato
    # per l'user per gli SMS  si potrebbe eventualmente pensare di usare HOTP al posto
    # di TOTP, per ovviare al problema del tempo di validità del token
    validation_result = pyotp.TOTP(user_secret, interval=interval).verify(token)
    logger.debug(
        "validate_token: token: %s %s %s", user_secret, token, validation_result
    )
    if user_secret_temp and validation_result:
        user.setMemberProperties({"two_factor_authentication_secret": user_secret})
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


def get_domain_name(request):
    """
    Gets domain name.
    """
    parsed_uri = urlparse(api.portal.get().absolute_url())
    return parsed_uri.netloc.split(":")[0]


def get_barcode_image(username, domain, secret):
    """
    Get barcode image URL.

    :param string username:
    :param string domain:
    :param string secret:
    :return string:
    """
    """
    params = urlencode(
        {
            "chs": "200x200",
            "chld": "M|0",
            "cht": "qr",
            "chl": f"otpauth://totp/{username}@{domain}?secret={secret}",
        }
    )
    # dont use google for generation
    # url = f"https://chart.googleapis.com/chart?{params}"
    """

    # use qrcode from pypi as inline base64 image
    url = f"otpauth://totp/{username}@{domain}?secret={secret}"
    image = qrcode.make(url)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    img_str = base64.b64encode(buffer.getvalue())
    return img_str.decode("utf-8")
