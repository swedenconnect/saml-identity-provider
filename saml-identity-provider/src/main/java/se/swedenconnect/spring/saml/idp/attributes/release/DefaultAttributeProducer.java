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
package se.swedenconnect.spring.saml.idp.attributes.release;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.spring.saml.idp.attributes.RequestedAttribute;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authnrequest.AuthenticationRequirements;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

/**
 * The default {@link AttributeProducer} that returns all attributes that are among the "requested list" (see
 * {@link Saml2UserAuthentication#getAuthnRequirements()}).
 * 
 * @author Martin Lindström
 */
public class DefaultAttributeProducer implements AttributeProducer {

  /**
   * Releases all attributes that are explicitly, or implicitly, requested.
   */
  @Override
  public List<Attribute> releaseAttributes(final Saml2UserAuthentication userAuthentication) {

    if (userAuthentication.getSaml2UserDetails().getAttributes().isEmpty()) {
      return Collections.emptyList();
    }

    final Collection<RequestedAttribute> requestedAttributes =
        Optional.ofNullable(userAuthentication.getAuthnRequirements())
            .map(AuthenticationRequirements::getRequestedAttributes)
            .orElseThrow(() -> new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL,
                "No authentication requirements available", userAuthentication));

    final List<Attribute> attributes = new ArrayList<>();
    for (final UserAttribute ua : userAuthentication.getSaml2UserDetails().getAttributes()) {
      if (requestedAttributes.stream().anyMatch(r -> Objects.equals(r.getId(), ua.getId()))) {
        attributes.add(ua.toOpenSamlAttribute());
      }
    }
    return attributes;
  }

}
