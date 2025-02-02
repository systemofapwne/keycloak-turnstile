package xyz.ofortune.app.keycloak

import jakarta.ws.rs.core.Response
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.AuthenticationFlowError
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialChooseUser
import org.keycloak.connections.httpclient.HttpClientProvider
import org.keycloak.models.*
import org.keycloak.models.utils.FormMessage
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.services.validation.Validation

class ResetCredentialsTurnstile : ResetCredentialChooseUser() {
    companion object {
        const val PROVIDER_ID = "rescreds-user-turnstile"
        const val DEFAULT_ACTION = "login-reset-credentials"
        private val REQUIREMENT_CHOICES = arrayOf(AuthenticationExecutionModel.Requirement.REQUIRED)
    }

    override fun authenticate(context: AuthenticationFlowContext) {
        val form = context.form()

        context.event.detail("auth_method", "reset_credentials_turnstile")

        val config = Turnstile.readConfig(context.authenticatorConfig.config, DEFAULT_ACTION)
        if (config == null) {
            form.addError(FormMessage(null, Turnstile.MSG_CAPTCHA_NOT_CONFIGURED))
            context.failureChallenge(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                form.createPasswordReset()
            )
            return
        }

        val lang = context.session.context.resolveLocale(context.user).toLanguageTag()
        Turnstile.prepareForm(form, config, lang)

        super.authenticate(context)
    }

    override fun action(context: AuthenticationFlowContext) {
        val formData = context.httpRequest.decodedFormParameters
        val captcha = formData.getFirst(Turnstile.CF_TURNSTILE_RESPONSE)

        context.event.detail("auth_method", "reset_credentials_turnstile")

        val config = Turnstile.readConfig(context.authenticatorConfig.config, DEFAULT_ACTION)
        if (config == null) {
            context.failureChallenge(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                challenge(context, Turnstile.MSG_CAPTCHA_NOT_CONFIGURED)
            )
            return
        }

        if (Validation.isBlank(captcha) ||
            !Turnstile.validate(
                config,
                captcha,
                context.connection.remoteAddr,
                context.session.getProvider(HttpClientProvider::class.java).httpClient
            )
        ) {

            val lang = context.session.context.resolveLocale(context.user).toLanguageTag()
            Turnstile.prepareForm(context.form(), config, lang)

            formData.remove(Turnstile.CF_TURNSTILE_RESPONSE)
            context.failureChallenge(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                challenge(context, Turnstile.MSG_CAPTCHA_FAILED)
            )

            return
        }

        super.action(context)
    }

    private fun challenge(context: AuthenticationFlowContext, message: String): Response {
        val form = context.form()
        form.addError(FormMessage(null, message))
        return form.createPasswordReset()
    }

    override fun getId(): String {
        return PROVIDER_ID
    }

    override fun getReferenceCategory(): String? {
        return Turnstile.TURNSTILE_REFERENCE_CATEGORY
    }

    override fun isConfigurable(): Boolean {
        return true
    }

    override fun getRequirementChoices(): Array<AuthenticationExecutionModel.Requirement> {
        return REQUIREMENT_CHOICES
    }

    override fun getDisplayType(): String {
        return "Chose user (with turnstile challenge)"
    }

    override fun getHelpText(): String {
        return "Choose a user to reset credentials for with added Turnstile challenge."
    }

    override fun getConfigProperties(): MutableList<ProviderConfigProperty> {
        return Turnstile.CONFIG_PROPERTIES
    }

    override fun isUserSetupAllowed(): Boolean {
        return false
    }
}