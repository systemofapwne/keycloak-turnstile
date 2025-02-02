import {
    KEYCLOAK_REALM,
    getAuthedClient,
    isTurnstileAuthenticatorConfigPreset,
    setResetCredentialsAuthBinding,
    setResetCredentialsFlowTurnstileConfig,
    type TurnstileAuthenticatorConfig,
    ResetCredentialsAuthFlow
} from "../keycloak";

const browserFlow: ResetCredentialsAuthFlow = process.argv[2] as ResetCredentialsAuthFlow ?? 'reset-credentials';
const turnstileConfig: TurnstileAuthenticatorConfig = process.argv[3] as TurnstileAuthenticatorConfig ?? 'client-visible-pass-server-pass';

async function main() {
    switch (browserFlow) {
        case 'reset-credentials': {
            await setResetCredentialsAuthBinding(await getAuthedClient(), KEYCLOAK_REALM, 'reset credentials');
            return;
        }
        case 'reset-credentials-turnstile': {
            if (!isTurnstileAuthenticatorConfigPreset(turnstileConfig)) {
                throw new Error(`Invalid turnstile config ${turnstileConfig}`);
            }
            await Promise.all(
                [
                    setResetCredentialsAuthBinding(await getAuthedClient(), KEYCLOAK_REALM, 'reset credentials-turnstile'),
                    setResetCredentialsFlowTurnstileConfig(await getAuthedClient(), KEYCLOAK_REALM, turnstileConfig)
                ]
            )
            return;
        }
    }
    throw new Error(`Invalid reset credentials flow ${browserFlow}`);
}

main();