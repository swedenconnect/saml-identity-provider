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

import java.util.Collection;

import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;

/**
 * Extends {@link Saml2Authentication} with information about the issued assertion.
 * <p>
 * The Spring Security developers did not think things through. The response is assigned to {@link Saml2Authentication},
 * but if encrypted assertions are being passed, we have little use of the response. Therefore, we assign the
 * (decrypted) SAML {@code Assertion} in our detailed {@code Saml2Authentication} object.
 * </p>
 *
 * @author Martin Lindström
 */
public class DetailedSaml2Authentication extends Saml2Authentication {

  private static final long serialVersionUID = -4895862417583908020L;

  private final SerializableOpenSamlObject<Assertion> assertion;

  public DetailedSaml2Authentication(
      final AuthenticatedPrincipal principal,
      final String saml2Response,
      final Assertion assertion,
      final Collection<? extends GrantedAuthority> authorities) {
    super(principal, saml2Response, authorities);
    this.assertion = new SerializableOpenSamlObject<Assertion>(assertion);
  }

  public Assertion getAssertion() {
    return this.assertion.get();
  }

}
