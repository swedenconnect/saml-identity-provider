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
package se.swedenconnect.spring.saml.idp.authentication.provider;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserDetails;
import se.swedenconnect.spring.saml.idp.authentication.provider.SsoVoter.Vote;
import se.swedenconnect.spring.saml.idp.authnrequest.AuthenticationRequirements;

/**
 * Test cases for PrincipalSelectionSsoVoter.
 *
 * @author Martin Lindström
 */
public class PrincipalSelectionSsoVoterTest {

  @Test
  public void testNoPrincipalSelection() {

    final Saml2UserAuthenticationInputToken token = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    final AuthenticationRequirements authnReqs = Mockito.mock(AuthenticationRequirements.class);
    Mockito.when(authnReqs.getPrincipalSelectionAttributes()).thenReturn(Collections.emptyList());
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReqs);

    final PrincipalSelectionSsoVoter voter = new PrincipalSelectionSsoVoter();
    Assertions.assertEquals(Vote.OK,
        voter.mayReuse(Mockito.mock(Saml2UserAuthentication.class), token, Collections.emptyList()));
  }

  @Test
  public void testOk() {
    final Saml2UserAuthenticationInputToken token = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    final AuthenticationRequirements authnReqs = Mockito.mock(AuthenticationRequirements.class);
    Mockito.when(authnReqs.getPrincipalSelectionAttributes()).thenReturn(
        List.of(new UserAttribute("One", "one", "1"), new UserAttribute("Two", "two"), new UserAttribute("Three", "three", "3")));
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReqs);

    final Saml2UserAuthentication userAuthn = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2UserDetails userDetails = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(userDetails.getAttributes()).thenReturn(
        List.of(new UserAttribute("One", "one", List.of("1", "ett")), new UserAttribute("Four", "four", "4")));
    Mockito.when(userAuthn.getSaml2UserDetails()).thenReturn(userDetails);

    final PrincipalSelectionSsoVoter voter = new PrincipalSelectionSsoVoter();
    Assertions.assertEquals(Vote.OK,
        voter.mayReuse(userAuthn, token, Collections.emptyList()));
  }

  @Test
  public void testOkMixedTypes() {
    final Saml2UserAuthenticationInputToken token = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    final AuthenticationRequirements authnReqs = Mockito.mock(AuthenticationRequirements.class);
    Mockito.when(authnReqs.getPrincipalSelectionAttributes()).thenReturn(
        List.of(new UserAttribute("One", "one", "1"), new UserAttribute("Two", "two"), new UserAttribute("Three", "three", "3")));
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReqs);

    final Saml2UserAuthentication userAuthn = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2UserDetails userDetails = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(userDetails.getAttributes()).thenReturn(
        List.of(new UserAttribute("One", "one", List.of("1", Integer.valueOf(1))), new UserAttribute("Four", "four", "4")));
    Mockito.when(userAuthn.getSaml2UserDetails()).thenReturn(userDetails);

    final PrincipalSelectionSsoVoter voter = new PrincipalSelectionSsoVoter();
    Assertions.assertEquals(Vote.OK,
        voter.mayReuse(userAuthn, token, Collections.emptyList()));
  }

  @Test
  public void testDeny() {
    final Saml2UserAuthenticationInputToken token = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    final AuthenticationRequirements authnReqs = Mockito.mock(AuthenticationRequirements.class);
    Mockito.when(authnReqs.getPrincipalSelectionAttributes()).thenReturn(
        List.of(new UserAttribute("One", "one", "1"), new UserAttribute("Two", "two"), new UserAttribute("Three", "three", "3")));
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReqs);

    final Saml2UserAuthentication userAuthn = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2UserDetails userDetails = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(userDetails.getAttributes()).thenReturn(
        List.of(new UserAttribute("One", "one", "ett"), new UserAttribute("Four", "four", "4")));
    Mockito.when(userAuthn.getSaml2UserDetails()).thenReturn(userDetails);

    final PrincipalSelectionSsoVoter voter = new PrincipalSelectionSsoVoter();
    Assertions.assertEquals(Vote.DENY,
        voter.mayReuse(userAuthn, token, Collections.emptyList()));
  }

}
