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

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserDetails;
import se.swedenconnect.spring.saml.idp.authentication.provider.SsoVoter.Vote;

/**
 * Test cases for BaseSsoVoter.
 * 
 * @author Martin Lindström
 */
public class BaseSsoVoterTest {

  @Test
  public void testMissingAuthnInstant() {
    final Saml2UserAuthentication userAuthn = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(details.getAuthnInstant()).thenReturn(null);
    Mockito.when(userAuthn.getSaml2UserDetails()).thenReturn(details);

    final BaseSsoVoter voter = new BaseSsoVoter();
    Assertions.assertEquals(Vote.DENY,
        voter.mayReuse(userAuthn, Mockito.mock(Saml2UserAuthenticationInputToken.class), Collections.emptyList()));
  }
  
  @Test
  public void testTooOld() {    
    final Instant now = Instant.now();
    
    final Saml2UserAuthentication userAuthn = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(userAuthn.getName()).thenReturn("USER");
    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(details.getAuthnInstant()).thenReturn(now.minus(Duration.ofHours(2)));
    Mockito.when(userAuthn.getSaml2UserDetails()).thenReturn(details);

    final Saml2UserAuthenticationInputToken input = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    Mockito.when(input.getLogString()).thenReturn("LOG");
    
    final BaseSsoVoter voter = new BaseSsoVoter();
    voter.setSsoDurationLimit(Duration.ofHours(1));
    Assertions.assertEquals(Vote.DENY,
        voter.mayReuse(userAuthn, input, Collections.emptyList()));
  }
  
  @Test
  public void testWrongLoa() {    
    final Instant now = Instant.now();
    
    final Saml2UserAuthentication userAuthn = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(userAuthn.getName()).thenReturn("USER");
    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(details.getAuthnInstant()).thenReturn(now.minus(Duration.ofMinutes(2)));
    Mockito.when(details.getAuthnContextUri()).thenReturn(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2);
    Mockito.when(userAuthn.getSaml2UserDetails()).thenReturn(details);

    final Saml2UserAuthenticationInputToken input = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    Mockito.when(input.getLogString()).thenReturn("LOG");
    
    final BaseSsoVoter voter = new BaseSsoVoter();
    Assertions.assertEquals(Vote.DENY,
        voter.mayReuse(userAuthn, input, List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)));
  }
  
  @Test
  public void testOk() {    
    final Instant now = Instant.now();
    
    final Saml2UserAuthentication userAuthn = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(userAuthn.getName()).thenReturn("USER");
    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(details.getAuthnInstant()).thenReturn(now.minus(Duration.ofMinutes(2)));
    Mockito.when(details.getAuthnContextUri()).thenReturn(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3);
    Mockito.when(userAuthn.getSaml2UserDetails()).thenReturn(details);

    final Saml2UserAuthenticationInputToken input = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    Mockito.when(input.getLogString()).thenReturn("LOG");
    
    final BaseSsoVoter voter = new BaseSsoVoter();
    Assertions.assertEquals(Vote.OK,
        voter.mayReuse(userAuthn, input, List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)));
  }

}
