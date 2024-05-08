/*
 * Copyright 2023-2024 Sweden Connect
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
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * An {@link SsoVoter} that ensures that SAML service providers that are registered as "signature services" never get
 * SSO. This is a function of the <a href="https://docs.swedenconnect.se/technical-framework/">Swedish eID
 * Framework</a>.
 *
 * @author Martin Lindström
 */
public class SignServiceSsoVoter implements SsoVoter {

  /** {@inheritDoc} */
  @Override
  public Vote mayReuse(final Saml2UserAuthentication userAuthn, final Saml2UserAuthenticationInputToken token,
      final Collection<String> allowedAuthnContexts) {

    // Get hold of the SP metadata and check if this is a signature service ...
    //
    final List<String> entityCategories = Optional.ofNullable(token.getAuthnRequestToken())
        .map(Saml2AuthnRequestAuthenticationToken::getPeerMetadata)
        .map(EntityDescriptorUtils::getEntityCategories)
        .orElseGet(Collections::emptyList);

    if (entityCategories.contains(EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE.getUri())) {
      return Vote.DENY;
    }

    return Vote.DONT_KNOW;
  }

}
