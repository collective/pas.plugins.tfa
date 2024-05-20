"""Module where all interfaces, events and exceptions live."""

from zope.publisher.interfaces.browser import IDefaultBrowserLayer


OTP_CHALLENGE_KEY = "pas.plugins.tfa.otp_challenge"


class IPasPluginsOtpLayer(IDefaultBrowserLayer):
    """Marker interface that defines a browser layer."""
