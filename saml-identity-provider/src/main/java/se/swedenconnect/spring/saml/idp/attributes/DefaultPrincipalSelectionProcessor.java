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
package se.swedenconnect.spring.saml.idp.attributes;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.PrincipalSelection;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Default implementation of the {@link PrincipalSelectionProcessor} interface.
 *
 * @author Martin Lindström
 */
@Slf4j
public class DefaultPrincipalSelectionProcessor implements PrincipalSelectionProcessor {

  /** {@inheritDoc} */
  @Override
  public Collection<UserAttribute> extractPrincipalSelection(
      final Saml2AuthnRequestAuthenticationToken authnRequestToken) {

    final PrincipalSelection principalSelection =
        Optional.ofNullable(authnRequestToken.getAuthnRequest().getExtensions())
            .map(e -> e.getUnknownXMLObjects(PrincipalSelection.DEFAULT_ELEMENT_NAME))
            .filter(list -> !list.isEmpty())
            .map(list -> list.get(0))
            .map(PrincipalSelection.class::cast)
            .orElse(null);
    if (principalSelection == null) {
      return Collections.emptyList();
    }

    final Collection<UserAttribute> attributes = principalSelection.getMatchValues().stream()
        .map(mv -> {
          final UserAttribute ua = new UserAttribute(mv.getName(), null, mv.getValue());
          ua.setNameFormat(mv.getNameFormat());
          return ua;
        })
        .collect(Collectors.toList());

    log.debug("Extracted PrincipalSelection attributes: {} [{}]",
        attributes, authnRequestToken.getLogString());

    return attributes;
  }

}
