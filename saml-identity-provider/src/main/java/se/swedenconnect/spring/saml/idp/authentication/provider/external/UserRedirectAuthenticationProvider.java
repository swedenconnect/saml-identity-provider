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
package se.swedenconnect.spring.saml.idp.authentication.provider.external;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.web.filters.Saml2UserAuthenticationProcessingFilter;

/**
 * If the user authentication is performed outside of the SAML IdP Spring Security flow an
 * {@link UserRedirectAuthenticationProvider} should be provided. The
 * {@link #authenticateUser(Saml2UserAuthenticationInputToken)} method of this provider should return a
 * {@link RedirectForAuthenticationToken} that tells the {@link Saml2UserAuthenticationProcessingFilter} where to
 * redirect the user agent for authentication.
 * <p>
 * The {@link #getResumeAuthnPath()} tells the path on where we expect the result ({@link ResumedAuthenticationToken})
 * to be delivered and this will lead to that the {@link #resumeAuthentication(ResumedAuthenticationToken)} is invoked.
 * </p>
 * 
 * @author Martin Lindström
 */
public interface UserRedirectAuthenticationProvider extends UserAuthenticationProvider {

  /**
   * Handles two types of tokens; {@link ResumedAuthenticationToken} if the method is invoked to resume an external
   * authentication, and {@link Saml2UserAuthenticationInputToken} to initiate an external authentication.
   */
  @Override
  default Authentication authenticate(final Authentication authentication) throws AuthenticationException {
    if (ResumedAuthenticationToken.class.isInstance(authentication)) {
      final ResumedAuthenticationToken resumeToken = ResumedAuthenticationToken.class.cast(authentication);
      if (!this.supportsUserAuthenticationToken(resumeToken.getAuthnToken())) {
        return null;
      }
      return this.resumeAuthentication(resumeToken);
    }
    try {
      return this.authenticateUser(Saml2UserAuthenticationInputToken.class.cast(authentication));
    }
    catch (final ClassCastException e) {
      return null;
    }
  }

  /**
   * Is invoked when the user has been authenticated outside of the SAML IdP Spring Security flow and the user agent has
   * been re-directed back to the {@link #getResumeAuthnPath()}.
   * 
   * @param token the {@link ResumedAuthenticationToken}
   * @return a {@link Saml2UserAuthentication}
   * @throws Saml2ErrorStatusException for authentication errors
   */
  Saml2UserAuthentication resumeAuthentication(final ResumedAuthenticationToken token)
      throws Saml2ErrorStatusException;

  /**
   * Supports {@link Saml2UserAuthenticationInputToken} and {@link ResumedAuthenticationToken}.
   */
  @Override
  default boolean supports(Class<?> authentication) {
    return UserAuthenticationProvider.super.supports(authentication)
        || ResumedAuthenticationToken.class.isAssignableFrom(authentication);
  }

  /**
   * Predicate that tells whether this provider supports the supplied {@link Authentication} object. With "supports" in
   * this case we mean: Can the supplied object be interpreted and give the input in the creation of a
   * {@link Saml2UserAuthentication} token.
   * 
   * @param authentication the {@link Authentication} object to test
   * @return {@code true} if the object is supported and {@code false} otherwise
   */
  boolean supportsUserAuthenticationToken(final Authentication authentication);

  /**
   * The provider, or any of its sub-components, uses an {@link ExternalAuthenticatorTokenRepository} to get hold of the
   * {@link RedirectForAuthenticationToken} that is the input for the external authentication process. It also uses the
   * repository to commit, or save, the result of an external authentication process (an {@link Authentication} object)
   * before the user agent is redirected back to the Spring Security flow. These method returns the
   * {@link ExternalAuthenticatorTokenRepository} that is used.
   * 
   * @return an {@link ExternalAuthenticatorTokenRepository}
   */
  ExternalAuthenticatorTokenRepository getTokenRepository();

  /**
   * Gets the path that the user agent should be redirected to in order to start the "external authentication process".
   * 
   * @return a path
   */
  String getAuthnPath();

  /**
   * Gets the path that is used by the "external authentication process" when redirecting the user agent back to the
   * SAML IdP Spring Security flow.
   * 
   * @return a path
   */
  String getResumeAuthnPath();

}
