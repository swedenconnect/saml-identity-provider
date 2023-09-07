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
package se.swedenconnect.spring.saml.idp.authentication.provider;

import java.util.Collection;
import java.util.Objects;

import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;

/**
 * An {@link SsoVoter} that checks that existing {@code PrincipalSelection} values corresponds with the previous
 * authentication.
 *
 * @author Martin Lindström
 */
public class PrincipalSelectionSsoVoter implements SsoVoter {

  /** {@inheritDoc} */
  @Override
  public Vote mayReuse(final Saml2UserAuthentication userAuthn, final Saml2UserAuthenticationInputToken token,
      final Collection<String> allowedAuthnContexts) {

    if (token.getAuthnRequirements().getPrincipalSelectionAttributes().isEmpty()) {
      return Vote.OK;
    }

    for (final UserAttribute ps : token.getAuthnRequirements().getPrincipalSelectionAttributes()) {
      if (ps.getValues().isEmpty()) {
        continue;
      }
      final String psValue = (String) ps.getValues().get(0);
      final UserAttribute attribute = userAuthn.getSaml2UserDetails().getAttributes().stream()
          .filter(u -> Objects.equals(ps.getId(), u.getId()))
          .findFirst()
          .orElse(null);
      if (attribute == null) {
        continue;
      }
      if (!attribute.getValues().contains(psValue)) {
        return Vote.DENY;
      }
    }

    return Vote.OK;
  }

}
