package xyz.ofortune.app.keycloak

import org.keycloak.WebAuthnConstants;
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.AuthenticationFlowError
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm
import org.keycloak.connections.httpclient.HttpClientProvider
import org.keycloak.events.Details
import org.keycloak.models.utils.FormMessage
import org.keycloak.services.validation.Validation
import org.keycloak.models.KeycloakSession

class LoginTurnstile(session: KeycloakSession?) : UsernamePasswordForm(session) {
    companion object {
        const val DEFAULT_ACTION = "login"
    }

    override fun authenticate(context: AuthenticationFlowContext) {
        val form = context.form()

        context.event.detail(Details.AUTH_METHOD, "auth_method")

        val config = Turnstile.readConfig(context.authenticatorConfig.config, DEFAULT_ACTION)
        if (config == null) {
            form.addError(FormMessage(null, Turnstile.MSG_CAPTCHA_NOT_CONFIGURED))
            return
        }

        val lang = context.session.context.resolveLocale(context.user).toLanguageTag()
        Turnstile.prepareForm(form, config, lang)

        super.authenticate(context)
    }

    override fun action(context: AuthenticationFlowContext) {
        val formData = context.httpRequest.decodedFormParameters
        val captcha = formData.getFirst(Turnstile.CF_TURNSTILE_RESPONSE)

        context.event.detail(Details.AUTH_METHOD, "auth_method")

        val config = Turnstile.readConfig(context.authenticatorConfig.config, DEFAULT_ACTION)
        if (config == null) {
            context.failureChallenge(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                challenge(context, Turnstile.MSG_CAPTCHA_NOT_CONFIGURED)
            )
            return
        }

        if (webauthnAuth != null && webauthnAuth.isPasskeysEnabled()
                && (formData.containsKey(WebAuthnConstants.AUTHENTICATOR_DATA) || formData.containsKey(WebAuthnConstants.ERROR))) {
            // webauth form submission, try to action using the webauthn authenticator
            webauthnAuth.action(context);
            return;
        } else  if (Validation.isBlank(captcha) || !Turnstile.validate(
                config,
                captcha,
                context.connection.remoteAddr,
                context.session.getProvider(HttpClientProvider::class.java).httpClient,
            )
        ) {
            formData.remove(Turnstile.CF_TURNSTILE_RESPONSE)
            context.failureChallenge(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                challenge(context, Turnstile.MSG_CAPTCHA_FAILED)
            )
            return
        } else {
            super.action(context)
        }
    }

    override fun close() {}
}
