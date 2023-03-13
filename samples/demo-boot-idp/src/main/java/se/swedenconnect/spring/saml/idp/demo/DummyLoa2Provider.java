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

import org.springframework.stereotype.Component;

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserDetails;
import se.swedenconnect.spring.saml.idp.authentication.provider.AbstractUserAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

//@Component
public class DummyLoa2Provider extends AbstractUserAuthenticationProvider {
  
  private static final String SUPPORTED_LOA = LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2;
  
  /** {@inheritDoc} */
  @Override
  public String getName() {
    return "Simulated Authentication Provider - LoA 2";
  }  

  @Override
  protected Saml2UserAuthentication authenticate(final Saml2UserAuthenticationInputToken token, final List<String> authnContextUris)
      throws Saml2ErrorStatusException {

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
        SUPPORTED_LOA, Instant.now(), "127.0.0.1");
        
    final Saml2UserAuthentication userAuthn = new Saml2UserAuthentication(details);
    userAuthn.setReuseAuthentication(true);
    
    return userAuthn;
  }

  @Override
  public List<String> getSupportedAuthnContextUris() {    
    return List.of(SUPPORTED_LOA);
  }

  @Override
  public List<String> getEntityCategories() {
    return List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA2_NAME.getUri(),
        EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA2_PNR.getUri(),
        EntityCategoryConstants.SERVICE_PROPERTY_CATEGORY_MOBILE_AUTH.getUri());
  }

}
