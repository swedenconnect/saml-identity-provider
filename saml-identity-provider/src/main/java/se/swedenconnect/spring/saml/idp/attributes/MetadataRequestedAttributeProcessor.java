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
import java.util.stream.Collectors;

import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * A {@link RequestedAttributeProcessor} that will check if the SAML SP metadata entry contains any requested attributes
 * by locating them in the {@code AttributeConsumingService} element.
 * 
 * @author Martin Lindström
 */
@Slf4j
public class MetadataRequestedAttributeProcessor implements RequestedAttributeProcessor {

  /** {@inheritDoc} */
  @Override
  public Collection<RequestedAttribute> extractRequestedAttributes(
      final Saml2AuthnRequestAuthenticationToken authnRequestToken) {

    final Integer index = authnRequestToken.getAuthnRequest().getAttributeConsumingServiceIndex();
    final SPSSODescriptor roleDescriptor =
        authnRequestToken.getPeerMetadata().getSPSSODescriptor(SAMLConstants.SAML20P_NS);

    AttributeConsumingService acs = null;
    for (final AttributeConsumingService a : roleDescriptor.getAttributeConsumingServices()) {
      if (index != null) {
        if (index.intValue() == a.getIndex()) {
          acs = a;
          break;
        }
      }
      else if (a.isDefault()) {
        acs = a;
        break;
      }
      else if (acs == null) {
        acs = a;
      }
      else if (a.getIndex() < acs.getIndex()) {
        acs = a;
      }
    }

    if (acs == null) {
      log.debug("No matching AttributeConsumingService found to extract requested attributes from [{}]",
          authnRequestToken.getLogString());

      return Collections.emptyList();
    }

    final Collection<RequestedAttribute> attributes = acs.getRequestedAttributes().stream()
        .map(RequestedAttribute::new)
        .collect(Collectors.toList());

    log.debug("Extracted requested attributes from AttributeConsumingService with index {} - {} [{}]",
        acs.getIndex(), attributes, authnRequestToken.getLogString());

    return attributes;
  }

}
