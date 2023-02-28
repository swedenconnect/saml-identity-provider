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
 * Abstract base class for {@link Saml2UserAuthenticationProvider}.
 * 
 * @author Martin Lindström
 */
@Slf4j
public abstract class AbstractSaml2UserAuthenticationProvider implements Saml2UserAuthenticationProvider {

  /** {@inheritDoc} */
  @Override
  public Authentication authenticate(final Authentication authentication) throws Saml2ErrorStatusException {

    final Saml2UserAuthenticationInputToken token = Saml2UserAuthenticationInputToken.class.cast(authentication);

    // Filter authentication context URI:s ...
    //
    final List<String> filteredAuthnContextUris = this.filterRequestedAuthnContextUris(token);

    // Check if we should apply SSO ...
    //
    if (token.getUserAuthentication() != null && !token.getAuthnRequirements().isForceAuthn()) {
      // authn context ...
    }

    // OK, no SSO. Check if passive authentication was requested ...
    //
    if (token.getAuthnRequirements().isPassiveAuthn()) {
      throw new Saml2ErrorStatusException(Saml2ErrorStatus.PASSIVE_AUTHN);
    }

    return null;
  }
  
  protected abstract Saml2UserAuthentication applySso(final Saml2UserAuthenticationInputToken token);
  
  // sso voters?
  // check authn context
  // check type

  /**
   * Given the requested authentication context URI:s, the method filters out those that are supported by the
   * {@link AuthenticationProvider}. If no authentication context URI:s are requested the method returns
   * {@link #getSupportedAuthnContextUris()}.
   * <p>
   * After filtering, if the resulting list is empty, an {@link Saml2ErrorStatusException} is thrown with
   * {@link Saml2ErrorStatus#NO_AUTHN_CONTEXT}.
   * </p>
   * 
   * @param token the {@link Saml2UserAuthenticationInputToken}
   * @return a filtered list of possible authentication context URI:s
   * @throws Saml2ErrorStatusException if none of the requested contexts are supported
   */
  protected List<String> filterRequestedAuthnContextUris(final Saml2UserAuthenticationInputToken token)
      throws Saml2ErrorStatusException {
    final List<String> supported = this.getSupportedAuthnContextUris();
    if (token.getAuthnRequirements().getAuthnContextRequirements().isEmpty()) {
      return supported;
    }
    final List<String> requestedUris = token.getAuthnRequirements().getAuthnContextRequirements().stream()
        .filter(a -> supported.contains(a))
        .collect(Collectors.toList());

    if (requestedUris.isEmpty()) {
      final String msg = String.format(
          "None of the requested authentication contexts (%s) are supported by the IdP",
          token.getAuthnRequirements().getAuthnContextRequirements());
      log.info("{} {}", msg, token.getAuthnRequestToken().getLogString());
      throw new Saml2ErrorStatusException(Saml2ErrorStatus.NO_AUTHN_CONTEXT, msg);
    }

    return requestedUris;
  }

}
