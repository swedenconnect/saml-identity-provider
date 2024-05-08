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
package se.swedenconnect.spring.saml.idp.attributes;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.stream.Collectors;

import org.opensaml.saml.ext.reqattr.RequestedAttributes;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * A {@link RequestedAttributeProcessor} that finds requested attributes from the {@link RequestedAttributes} extension.
 * See
 * <a href="https://docs.oasis-open.org/security/saml-protoc-req-attr-req/v1.0/saml-protoc-req-attr-req-v1.0.html">SAML
 * V2.0 Protocol Extension for Requesting Attributes per Request Version 1.0</a>.
 * 
 * @author Martin Lindström
 */
@Slf4j
public class OasisExtensionRequestedAttributeProcessor implements RequestedAttributeProcessor {

  /** {@inheritDoc} */
  @Override
  public Collection<RequestedAttribute> extractRequestedAttributes(
      final Saml2AuthnRequestAuthenticationToken authnRequestToken) {
    
    final RequestedAttributes requestedAttributes =
        Optional.ofNullable(authnRequestToken.getAuthnRequest().getExtensions())
            .map(e -> e.getUnknownXMLObjects(RequestedAttributes.DEFAULT_ELEMENT_NAME))
            .filter(list -> !list.isEmpty())
            .map(list -> list.get(0))
            .map(RequestedAttributes.class::cast)
            .orElse(null);

    if (requestedAttributes == null) {
      return Collections.emptyList();
    }

    final Collection<RequestedAttribute> attributes = requestedAttributes.getRequestedAttributes().stream()
        .map(RequestedAttribute::new)
        .collect(Collectors.toList());

    log.debug("Extracted requested attributes from RequestedAttributes extension - {} [{}]",
        attributes, authnRequestToken.getLogString());
    
    return attributes;
  }

}
