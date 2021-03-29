package com.jangaraj.keycloak.authenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.jboss.logging.Logger;
//import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.credential.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;

public class ConditionalOtpAuthenticator implements ConditionalAuthenticator {
    public static final ConditionalOtpAuthenticator SINGLETON = new ConditionalOtpAuthenticator();
    private static final Logger logger = Logger.getLogger(ConditionalOtpAuthenticator.class);

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();

        OTPCredentialProvider otpProvider = (OTPCredentialProvider) session.getProvider(CredentialProvider.class, OTPCredentialProviderFactory.PROVIDER_ID);
        // https://www.keycloak.org/docs-api/12.0/javadocs/org/keycloak/credential/OTPCredentialProvider.html
        return otpProvider.isConfiguredFor(realm, user);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Not used
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Not used
    }

    @Override
    public void close() {
        // Does nothing
    }
}
