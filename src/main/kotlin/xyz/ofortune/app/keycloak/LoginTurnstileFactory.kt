package xyz.ofortune.app.keycloak

import org.keycloak.Config
import org.keycloak.authentication.Authenticator
import org.keycloak.authentication.AuthenticatorFactory
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm
import org.keycloak.models.AuthenticationExecutionModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ProviderConfigProperty

class LoginTurnstileFactory : UsernamePasswordFormFactory() {
    companion object {
        const val PROVIDER_ID = "login-turnstile-action"
    }

    override fun create(session: KeycloakSession?): Authenticator {
        return LoginTurnstile(session)
    }

    override fun init(config: Config.Scope?) {
    }

    override fun postInit(factory: KeycloakSessionFactory?) {
    }

    override fun close() {
    }

    override fun getId(): String {
        return PROVIDER_ID
    }

    override fun getHelpText(): String {
        return "Validates a username and password from a form and adds Cloudflare Turnstile button."
    }

    override fun getConfigProperties(): MutableList<ProviderConfigProperty> {
        return Turnstile.CONFIG_PROPERTIES
    }

    override fun getDisplayType(): String {
        return "Turnstile Username Password Form"
    }

    override fun getReferenceCategory(): String {
        return Turnstile.TURNSTILE_REFERENCE_CATEGORY
    }

    override fun isConfigurable(): Boolean {
        return true
    }

    override fun getRequirementChoices(): Array<AuthenticationExecutionModel.Requirement> {
        return arrayOf(AuthenticationExecutionModel.Requirement.REQUIRED)
    }

    override fun isUserSetupAllowed(): Boolean {
        return false
    }

}