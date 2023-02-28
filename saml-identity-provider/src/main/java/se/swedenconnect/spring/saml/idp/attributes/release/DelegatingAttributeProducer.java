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
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.utils.Saml2IdentityProviderVersion;

/**
 * A delegating {@link AttributeProducer} that delegates to a list of producers and returns attributes from all
 * underlying producers (no duplicates).
 * 
 * @author Martin Lindström
 */
public class DelegatingAttributeProducer implements AttributeProducer {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The attribute producers. */
  private final List<AttributeProducer> producers;

  /**
   * Constructor.
   * 
   * @param producers a list of {@link AttributeProducer} instances
   */
  public DelegatingAttributeProducer(final List<AttributeProducer> producers) {
    this.producers = Optional.ofNullable(producers)
        .filter(p -> !p.isEmpty())
        .orElseThrow(() -> new IllegalArgumentException("At least on producer must be provided"));
  }

  /** {@inheritDoc} */
  @Override
  public List<Attribute> releaseAttributes(final Saml2UserAuthentication userAuthentication) {
    final List<Attribute> attributes = new ArrayList<>();
    for (final AttributeProducer p : this.producers) {
      final List<Attribute> pattrs = p.releaseAttributes(userAuthentication);
      pattrs.forEach((attr) -> {
        if (attributes.stream().noneMatch(a -> Objects.equals(a.getName(), attr.getName()))) {
          attributes.add(attr);
        }
      });
    }
    return attributes;
  }

}
