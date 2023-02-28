/*
 * Copyright 2023 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.spring.saml.idp.authentication.provider;

import java.time.Duration;
import java.time.Instant;

import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

public class BaseSsoVoter implements SsoVoter {

  private Duration ssoLimit = IdentityProviderSettings.SSO_DURATION_LIMIT_DEFAULT;

  @Override
  public Vote mayReuse(final Saml2UserAuthentication userAuthn, final Saml2UserAuthenticationInputToken token) {
    if (userAuthn == null || userAuthn.getSaml2UserDetails().getAuthnInstant() == null) {
      return Vote.DENY;
    }
    if (!userAuthn.isReuseAuthentication()) {
      // Should never happen ...
      return Vote.DENY;
    }
    
    // Too old?
    if (userAuthn.getSaml2UserDetails().getAuthnInstant().plus(this.ssoLimit).isBefore(Instant.now())) {      
      return Vote.DENY;
    }
    
    // Compare the requested authentication context

    return Vote.OK;
  }

}
