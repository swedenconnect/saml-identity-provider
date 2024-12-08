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
package se.swedenconnect.spring.saml.testsp.ext;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;

public class ExtendedSaml2AuthenticationTokenConverter implements AuthenticationConverter {

  private final Saml2AuthenticationTokenConverter delegate;

  public ExtendedSaml2AuthenticationTokenConverter(
      final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
    this.delegate = new Saml2AuthenticationTokenConverter(relyingPartyRegistrationResolver);
  }

  @Override
  public Authentication convert(final HttpServletRequest request) {
    final Saml2AuthenticationToken authn = this.delegate.convert(request);

    return new ExtendedSaml2AuthenticationToken(authn.getRelyingPartyRegistration(), authn.getSaml2Response(),
        authn.getAuthenticationRequest());
  }

}
