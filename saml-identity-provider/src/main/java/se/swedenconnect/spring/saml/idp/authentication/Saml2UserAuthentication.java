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
package se.swedenconnect.spring.saml.idp.authentication;

import java.time.Instant;
import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.utils.Saml2IdentityProviderVersion;

/**
 * An {@link Authentication} token that represents the authentication of a user. 
 * 
 * @author Martin Lindström
 */
public class Saml2UserAuthentication extends AbstractAuthenticationToken {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;
  
  private final Saml2AuthnRequestAuthenticationToken authnRequestToken;

  public Saml2UserAuthentication(
      final Saml2AuthnRequestAuthenticationToken authnRequest) {
    super(Collections.emptyList());
    this.authnRequestToken = authnRequest;
    this.setAuthenticated(false);
  }
  
  public Instant getAuthnInstant() {
    return null;
  }
  
  
  @Override
  public Object getCredentials() {
    return "";
  }

  @Override
  public Object getPrincipal() {
    return null;
  }

  public Saml2AuthnRequestAuthenticationToken getAuthnRequestToken() {
    return this.authnRequestToken;
  }

}
