/*
 * Copyright 2023-2025 Sweden Connect
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

import jakarta.annotation.Nonnull;
import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml5AuthenticationProvider.ResponseToken;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml5AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

@Component
public class ResponseAuthenticationConverter implements Converter<ResponseToken, Saml2Authentication> {

  @Override
  public Saml2Authentication convert(@Nonnull final ResponseToken responseToken) {

    final Saml2Authentication token =
        OpenSaml5AuthenticationProvider.createDefaultResponseAuthenticationConverter().convert(responseToken);

    final Assertion assertion = CollectionUtils.firstElement(responseToken.getResponse().getAssertions());

    return new DetailedSaml2Authentication((AuthenticatedPrincipal) token.getPrincipal(),
        token.getSaml2Response(), assertion, token.getAuthorities());

  }

}
