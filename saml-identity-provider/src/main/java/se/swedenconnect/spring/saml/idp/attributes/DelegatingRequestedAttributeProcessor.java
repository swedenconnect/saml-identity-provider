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
package se.swedenconnect.spring.saml.idp.attributes;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * An implementation of the {@link RequestedAttributeProcessor} interface that delegates to a collection of underlying
 * processors.
 * 
 * @author Martin Lindström
 */
public class DelegatingRequestedAttributeProcessor implements RequestedAttributeProcessor {

  /** The actual processors. */
  private List<RequestedAttributeProcessor> processors;

  /**
   * Constructor.
   * 
   * @param processors the underlying processors
   */
  public DelegatingRequestedAttributeProcessor(final List<RequestedAttributeProcessor> processors) {
    this.processors = Objects.requireNonNull(processors, "processors must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public Collection<RequestedAttribute> extractRequestedAttributes(
      final Saml2AuthnRequestAuthenticationToken authnRequestToken) {

    final List<RequestedAttribute> attributes = new ArrayList<>();

    for (final RequestedAttributeProcessor p : this.processors) {
      final Collection<RequestedAttribute> pattrs = p.extractRequestedAttributes(authnRequestToken);
      for (final RequestedAttribute r : pattrs) {
        final RequestedAttribute attr =
            attributes.stream().filter(a -> Objects.equals(a.getId(), r.getId())).findAny().orElse(null);
        if (attr != null) {
          attr.setRequired(attr.isRequired() && r.isRequired());
        }
        else {
          attributes.add(r);
        }
      }
    }

    return attributes;
  }

}
