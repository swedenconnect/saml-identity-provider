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

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

/**
 * Abstract base class for {@link UserAuthenticationProvider}.
 * 
 * @author Martin Lindström
 */
@Slf4j
public abstract class AbstractUserAuthenticationProvider implements UserAuthenticationProvider {

  /** An ordered list of {@link SsoVoter}s that is used to decide whether SSO should be allowed. */
  private final List<SsoVoter> ssoVoters;

  /**
   * Constructor.
   */
  public AbstractUserAuthenticationProvider() {
    this.ssoVoters = new ArrayList<>();
    this.ssoVoters.add(new BaseSsoVoter());
    this.ssoVoters.add(new SignServiceSsoVoter());
  }

  /** {@inheritDoc} */
  @Override
  public Authentication authenticateUser(final Saml2UserAuthenticationInputToken token)
      throws Saml2ErrorStatusException {

    // Filter authentication context URI:s ...
    //
    final List<String> filteredAuthnContextUris = this.filterRequestedAuthnContextUris(token);
    if (filteredAuthnContextUris.isEmpty()) {
      final String msg = String.format(
          "None of the requested authentication contexts ({}) are supported by provider {}",
          token.getAuthnRequirements().getAuthnContextRequirements(), this.getClass().getSimpleName());
      log.info("{} [{}]", msg, token.getAuthnRequestToken().getLogString());
      return null;
    }

    // Check if we should apply SSO ...
    //
    final Saml2UserAuthentication ssoAuthentication = this.applySso(token, filteredAuthnContextUris);
    if (ssoAuthentication != null) {
      log.info("SSO: {} decided to re-use authentication for '{}' [{}]", ssoAuthentication.getName(),
          token.getLogString());
      return ssoAuthentication;
    }

    // OK, no SSO. Check if passive authentication was requested ...
    //
    if (token.getAuthnRequirements().isPassiveAuthn()) {
      throw new Saml2ErrorStatusException(Saml2ErrorStatus.PASSIVE_AUTHN);
    }

    return this.authenticate(token, filteredAuthnContextUris);
  }

  /**
   * Authenticates the user (after the necessary checks have been made).
   * 
   * @param token the input token
   * @param authnContextUris the possible authentication context URI:s
   * @return an authentication token
   * @throws Saml2ErrorStatusException for authentication errors
   */
  protected abstract Authentication authenticate(final Saml2UserAuthenticationInputToken token,
      final List<String> authnContextUris) throws Saml2ErrorStatusException;

  /**
   * Applies the rules for re-using authentication, i.e., SSO. If a previous authentication may be re-used its
   * {@link Saml2UserAuthentication} is returned. Otherwise {@code null}.
   * 
   * @param token the {@link Saml2UserAuthenticationInputToken}
   * @param authnContextUris filtered authentication context URI:s that are allowed
   * @return a {@link Saml2UserAuthenticationInputToken} for SSO and {@code null} otherwise
   */
  protected Saml2UserAuthentication applySso(final Saml2UserAuthenticationInputToken token,
      final List<String> authnContextUris) {
    if (token.getUserAuthentication() == null) {
      return null;
    }
    if (token.getAuthnRequirements().isForceAuthn()) {
      return null;
    }
    if (!Saml2UserAuthentication.class.isInstance(token.getUserAuthentication())) {
      return null;
    }
    final Saml2UserAuthentication userAuth = Saml2UserAuthentication.class.cast(token.getUserAuthentication());
    if (!userAuth.isReuseAuthentication()) {
      return null;
    }

    SsoVoter.Vote currentVote = SsoVoter.Vote.DONT_KNOW;
    for (final SsoVoter voter : this.ssoVoters) {
      final SsoVoter.Vote vote = voter.mayReuse(userAuth, token, authnContextUris);
      if (vote == SsoVoter.Vote.DENY) {
        return null;
      }
      if (vote == SsoVoter.Vote.OK) {
        currentVote = SsoVoter.Vote.OK;
      }
    }
    if (currentVote == SsoVoter.Vote.DONT_KNOW) {
      // None of the voters denied, but none said OK either. We don't allow SSO ...
      return null;
    }
    return userAuth;
  }

  /**
   * Given the requested authentication context URI:s, the method filters out those that are supported by the
   * {@link AuthenticationProvider}. If no authentication context URI:s are requested the method returns
   * {@link #getSupportedAuthnContextUris()}.
   * 
   * @param token the {@link Saml2UserAuthenticationInputToken}
   * @return a filtered list of possible authentication context URI:s (may be empty)
   */
  protected List<String> filterRequestedAuthnContextUris(final Saml2UserAuthenticationInputToken token) {
    final List<String> supported = this.getSupportedAuthnContextUris();
    if (token.getAuthnRequirements().getAuthnContextRequirements().isEmpty()) {
      return supported;
    }
    return token.getAuthnRequirements().getAuthnContextRequirements().stream()
        .filter(a -> supported.contains(a))
        .collect(Collectors.toList());
  }

  /**
   * Returns a modifiable list of the installed {@link SsoVoter}s.
   * 
   * @return a modifiable list of the installed {@link SsoVoter}s
   */
  public List<SsoVoter> ssoVoters() {
    return this.ssoVoters;
  }

}
