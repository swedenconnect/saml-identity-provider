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
package se.swedenconnect.spring.saml.idp.demo;

import java.time.Instant;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserDetails;

@Component
public class DummyAuthnProvider implements Saml2UserAuthenticationProvider {

  @Override
  public Authentication authenticate(final Authentication authentication) throws AuthenticationException {

    final Saml2UserAuthenticationInputToken token = Saml2UserAuthenticationInputToken.class.cast(authentication);

    final List<UserAttribute> attributes = List.of(
        new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER, "194911172296"),
        new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME, "Sven"),
        new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_SN,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SN, "Svensson"),
        new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DISPLAY_NAME, "Sven Svensson"));
    
    final Saml2UserDetails details = new Saml2UserDetails(attributes, AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
        "http://id.elegnamnden.se/loa/1.0/loa3", Instant.now(), "127.0.0.1");
        

    return new Saml2UserAuthentication(details);
  }

}
