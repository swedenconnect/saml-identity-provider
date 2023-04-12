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
import java.util.Collection;
import java.util.Objects;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

/**
 * A {@link SsoVoter} that checks basic conditions. It denies SSO for the following cases:
 * <ul>
 * <li>The time that has passed since the original authentication exceeds the configured limit.</li>
 * <li>The authentication context used in the original authentication does not match the current request or the ones
 * supported by the IdP.</li>
 * </ul>
 * 
 * @author Martin Lindström
 */
@Slf4j
public class BaseSsoVoter implements SsoVoter {

  /**
   * The the limit for accepting an older authentication for SSO (compared from its original authentication instant).
   */
  private Duration ssoDurationLimit = IdentityProviderSettings.SSO_DURATION_LIMIT_DEFAULT;

  /** {@inheritDoc} */
  @Override
  public Vote mayReuse(final Saml2UserAuthentication userAuthn, final Saml2UserAuthenticationInputToken token,
      final Collection<String> allowedAuthnContexts) {

    if (userAuthn.getSaml2UserDetails().getAuthnInstant() == null) {
      return Vote.DENY;
    }

    // Too old?
    if (userAuthn.getSaml2UserDetails().getAuthnInstant().plus(this.ssoDurationLimit).isBefore(Instant.now())) {
      log.info("Will not re-use authentication for '{}' - authn-instant exceeds limit [{}]",
          userAuthn.getName(), token.getLogString());

      return Vote.DENY;
    }

    // Compare the requested authentication context
    //
    if (!allowedAuthnContexts.contains(userAuthn.getSaml2UserDetails().getAuthnContextUri())) {
      log.info("Will not re-use authentication for '{}' - "
          + "previous authentication was made according to '{}' - not matched by IdP or AuthnRequest [{}]",
          userAuthn.getName(), userAuthn.getSaml2UserDetails().getAuthnContextUri(), token.getLogString());
      return Vote.DENY;
    }

    return Vote.OK;
  }

  /**
   * Assigns the limit for accepting an older authentication for SSO (compared from its original authentication
   * instant). The default is {@link IdentityProviderSettings#SSO_DURATION_LIMIT_DEFAULT}.
   * 
   * @param ssoDurationLimit the duration
   */
  public void setSsoDurationLimit(final Duration ssoDurationLimit) {
    this.ssoDurationLimit = Objects.requireNonNull(ssoDurationLimit, "ssoDurationLimit must not be null");
  }

}
