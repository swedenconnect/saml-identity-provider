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
package se.swedenconnect.spring.saml.idp.demo.authn;

import org.springframework.security.core.Authentication;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserDetails;
import se.swedenconnect.spring.saml.idp.authentication.provider.external.AbstractUserRedirectAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.authentication.provider.external.ResumedAuthenticationToken;
import se.swedenconnect.spring.saml.idp.demo.user.SimulatedUser;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

import java.time.Instant;
import java.util.List;

/**
 * Simulated authentication provider.
 *
 * @author Martin Lindström
 */
public class SimulatedAuthenticationProvider extends AbstractUserRedirectAuthenticationProvider {

  /** The supported authentication context URI:s. */
  private static final List<String> SUPPORTED_LOAS = List.of(
      LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3,
      LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA3);

  /**
   * Constructor.
   *
   * @param authnPath the path to where we redirect the user for authentication
   * @param resumeAuthnPath the path that the authentication process uses to redirect the user back after a
   *     completed authentication
   */
  public SimulatedAuthenticationProvider(final String authnPath, final String resumeAuthnPath) {
    super(authnPath, resumeAuthnPath);
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return "Simulated Authentication Provider - LoA 3";
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getSupportedAuthnContextUris() {
    return SUPPORTED_LOAS;
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getEntityCategories() {
    return List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_NAME.getUri(),
        EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri(),
        EntityCategoryConstants.SERVICE_PROPERTY_CATEGORY_MOBILE_AUTH.getUri());
  }

  /** {@inheritDoc} */
  @Override
  public Saml2UserAuthentication resumeAuthentication(final ResumedAuthenticationToken token)
      throws Saml2ErrorStatusException {

    final SimulatedAuthenticationToken simAuth = (SimulatedAuthenticationToken) token.getAuthnToken();
    final SimulatedUser user = (SimulatedUser) simAuth.getDetails();

    final List<UserAttribute> attributes = List.of(
        new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER, user.getPersonalNumber()),
        new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME, user.getGivenName()),
        new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_SN,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SN, user.getSurname()),
        new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DISPLAY_NAME, user.getDisplayName()),
        new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DATE_OF_BIRTH, user.getDateOfBirth()));

    final Saml2UserDetails userDetails = new Saml2UserDetails(attributes,
        AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3,
        Instant.now(), token.getServletRequest().getRemoteAddr());

    final Saml2UserAuthentication userAuth = new Saml2UserAuthentication(userDetails);

    // Allow future SSO
    userAuth.setReuseAuthentication(true);

    return userAuth;
  }

  /** {@inheritDoc} */
  @Override
  public boolean supportsUserAuthenticationToken(final Authentication authentication) {
    return authentication instanceof SimulatedAuthenticationToken;
  }

}
