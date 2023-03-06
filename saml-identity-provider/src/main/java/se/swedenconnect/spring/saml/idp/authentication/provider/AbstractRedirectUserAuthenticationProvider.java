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

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.saml.idp.attributes.RequestedAttribute;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authnrequest.AuthenticationRequirements;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.extensions.SignatureMessageExtension;
import se.swedenconnect.spring.saml.idp.utils.Saml2IdentityProviderVersion;

public abstract class AbstractRedirectUserAuthenticationProvider extends AbstractUserAuthenticationProvider {

  /** The path to where we redirect the user for authentication. */
  private final String authnPath;

  /** The repository where we store the output token. */
  private ExternalAuthenticationRepository externalAuthenticationRepository =
      new SessionBasedExternalAuthenticationRepository();

  /**
   * The path that the authenticator uses to redirect the user back after a completed authentication (successful or
   * not).
   */
  private final String resumeAuthnPath;

  public AbstractRedirectUserAuthenticationProvider(final String authnPath, final String resumeAuthnPath) {
    this.authnPath = Optional.ofNullable(authnPath)
        .map(String::trim)
        .filter(p -> p.startsWith("/"))
        .orElseThrow(() -> new IllegalArgumentException("authnPath must be set and begin with a '/'"));
    this.resumeAuthnPath = Optional.ofNullable(resumeAuthnPath)
        .map(String::trim)
        .filter(p -> p.startsWith("/"))
        .orElseThrow(() -> new IllegalArgumentException("resumeAuthnPath must be set and begin with a '/'"));
  }

  @Override
  public Authentication authenticate(final Authentication authentication) throws Saml2ErrorStatusException {
    if (ResumedAuthenticationToken.class.isInstance(authentication)) {
      final ResumedAuthenticationToken resumeToken = ResumedAuthenticationToken.class.cast(authentication); 
      if (!this.supportsUserAuthenticationToken(resumeToken.getAuthnToken())) {
        return null;
      }
      return this.resumeAuthentication(resumeToken);
    }
    return super.authenticate(authentication);
  }

  /**
   * Will redirect to the configured authentication path ({@link #getAuthnPath()}) by returning a
   * {@link RedirectForAuthenticationToken}.
   */
  @Override
  protected Authentication authenticate(
      final Saml2UserAuthenticationInputToken token, final List<String> authnContextUris)
      throws Saml2ErrorStatusException {

    final Saml2UserAuthenticationInputToken updatedToken =
        new Saml2UserAuthenticationInputToken(token.getAuthnRequestToken(),
            new AuthenticationRequirements() {

              private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

              @Override
              public boolean isForceAuthn() {
                return token.getAuthnRequirements().isForceAuthn();
              }

              @Override
              public boolean isPassiveAuthn() {
                return token.getAuthnRequirements().isPassiveAuthn();
              }

              @Override
              public Collection<String> getEntityCategories() {
                return token.getAuthnRequirements().getEntityCategories();
              }

              @Override
              public Collection<RequestedAttribute> getRequestedAttributes() {
                return token.getAuthnRequirements().getRequestedAttributes();
              }

              @Override
              public Collection<String> getAuthnContextRequirements() {
                return authnContextUris;
              }

              @Override
              public Collection<UserAttribute> getPrincipalSelectionAttributes() {
                return token.getAuthnRequirements().getPrincipalSelectionAttributes();
              }

              @Override
              public SignatureMessageExtension getSignatureMessageExtension() {
                return token.getAuthnRequirements().getSignatureMessageExtension();
              }

            });

    return new RedirectForAuthenticationToken(updatedToken, this.authnPath, this.resumeAuthnPath);
  }

  protected abstract Saml2UserAuthentication resumeAuthentication(final ResumedAuthenticationToken token)
      throws Saml2ErrorStatusException;

  @Override
  public boolean supports(final Class<?> authentication) {
    return super.supports(authentication) || ResumedAuthenticationToken.class.isAssignableFrom(authentication);        
  }

  protected abstract boolean supportsUserAuthenticationToken(final Authentication authentication);

  public String getAuthnPath() {
    return this.authnPath;
  }

  public String getResumeAuthnPath() {
    return this.resumeAuthnPath;
  }

  public void setExternalAuthenticationRepository(
      final ExternalAuthenticationRepository externalAuthenticationRepository) {
    this.externalAuthenticationRepository =
        Objects.requireNonNull(externalAuthenticationRepository, "externalAuthenticationRepository must not be null");
  }

}
