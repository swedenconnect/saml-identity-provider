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

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import java.io.Serial;

public class ExtendedSaml2AuthenticationToken extends Saml2AuthenticationToken {

  @Serial
  private static final long serialVersionUID = -3655430597897721039L;

  @Getter
  @Setter
  private String authnContextClassRef;

  public ExtendedSaml2AuthenticationToken(final RelyingPartyRegistration relyingPartyRegistration, final String saml2Response,
      final AbstractSaml2AuthenticationRequest authenticationRequest) {
    super(relyingPartyRegistration, saml2Response, authenticationRequest);
  }

}
