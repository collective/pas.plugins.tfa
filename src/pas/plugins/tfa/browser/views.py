# -*- coding: utf-8 -*-
from plone import api
from plone.autoform.form import AutoExtensibleForm
from plone.supermodel import model
from plone.z3cform.layout import wrap_form
from Products.statusmessages.interfaces import IStatusMessage
from z3c.form import button
from z3c.form import field
from z3c.form import form
from zope.schema import TextLine

from .. import logger
from ..helpers import drop_login_failed_msg
from ..helpers import validate_token
from ..helpers import validate_user_data
from .. import _
from .. import PMF


class ITokenForm(model.Schema):
    """
    Interface for the 2FA Token validation form.
    """

    token = TextLine(
        title=_("Enter code"),
        description=_("Enter the verification code."),
        required=True,
    )


class TokenForm(AutoExtensibleForm, form.Form):
    """
    Form for the 2FA Token validation. Any user that has
    two-step verification enabled, uses this form upon logging in.
    """

    fields = field.Fields(ITokenForm)
    ignoreContext = True
    schema = ITokenForm
    label = _("Two-step verification")
    # TODO: questo va personalizzato in base al device 2FA dell'utente
    description = _("Confirm your login by entering the verification " "token.")

    def action(self):
        return "{0}?{1}".format(
            self.request.getURL(), self.request.get("QUERY_STRING", "")
        )

    @button.buttonAndHandler(_("Verify"))
    def handleSubmit(self, action):
        """
        Here we should check couple of things:

        - If the token provided is valid.
        - If the signature contains the user data needed (username and hash
          made of his data are valid).

        If all is well and valid, we sudo login the user given.
        """
        data, errors = self.extractData()
        if errors:
            return False

        token = data.get("token", "")

        user = None
        username = self.request.get("auth_user", "")

        if username:
            user = api.user.get(username=username)

            # Validating the signed request data. If invalid (likely tampered
            # with or expired), generate an appropriate error message.
            user_data_validation_result = validate_user_data(
                request=self.request, user=user
            )

            if not user_data_validation_result.result:
                # TODO: se c'è il rendering e non un redirect, lo status message viene perso
                IStatusMessage(self.request).addStatusMessage(
                    _(
                        "Invalid data. Details: {0}".format(
                            " ".join(user_data_validation_result.reason)
                        )
                    ),
                    "error",
                )
                return

        logger.info("validate token %s %s", user, token)
        valid_token = validate_token(token, user=user)
        # self.context.plone_log(valid_token)
        # self.context.plone_log(token)

        if valid_token:
            # We should login the user here
            # TODO: generalizzare / notificare evento di login
            self.context.acl_users.session._setupSession(
                str(username), self.context.REQUEST.RESPONSE
            )
            msg = PMF("Welcome! You are now logged in.")
            IStatusMessage(self.request).addStatusMessage(msg, "info")
            context_url = self.context.absolute_url()
            redirect_url = self.request.get("next_url", context_url)
            self.request.response.redirect(redirect_url)
        else:
            # TODO: se c'è il rendering e non un redirect, lo status message viene perso
            msg = _("Invalid token or token expired.")
            IStatusMessage(self.request).addStatusMessage(msg, "error")

    def updateFields(self, *args, **kwargs):
        """
        Here we clear the status messages to drop the "Login failed" message
        that appears because we consumed the credentials in our own
        IAuthenticationPlugin (after verifying the creds ourselves), and
        therefore none of the other auth plugins get a chance to log the
        user in.

        We will do that ourselves in the handleSubmit() above, but only once
        the user entered a valid token.
        """
        logger.debug("Landed in the token hook.")

        request = self.request
        response = request["RESPONSE"]
        response.setCookie("__ac", "", path="/")

        # Drop the "Login failed" message that appears because we consumed
        # the credentials in our authenticator plugin.
        drop_login_failed_msg(request)

        # Updating the description
        token_field = self.fields.get("token")
        if token_field:
            token_field.field.description = _("Enter the verification code.")

        return super(TokenForm, self).updateFields(*args, **kwargs)


# View for the ``TokenForm``.
TokenFormView = wrap_form(TokenForm)
