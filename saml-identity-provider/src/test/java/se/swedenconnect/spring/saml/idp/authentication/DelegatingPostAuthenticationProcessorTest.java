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
package se.swedenconnect.spring.saml.idp.authentication;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import lombok.Getter;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

/**
 * Test cases for DelegatingPostAuthenticationProcessor.
 * 
 * @author Martin Lindström
 */
public class DelegatingPostAuthenticationProcessorTest {

  @Test
  public void testNull() {
    final DelegatingPostAuthenticationProcessor dp = new DelegatingPostAuthenticationProcessor(null);
    dp.process(Mockito.mock(Saml2UserAuthentication.class));
  }

  @Test
  public void testInvokeAll() {
    final TestProcessor t1 = new TestProcessor();
    final TestProcessor t2 = new TestProcessor();
    
    final DelegatingPostAuthenticationProcessor dp = new DelegatingPostAuthenticationProcessor(List.of(t1, t2));
    dp.process(Mockito.mock(Saml2UserAuthentication.class));
    
    Assertions.assertTrue(t1.getInvoked() == 1);
    Assertions.assertTrue(t2.getInvoked() == 1);
  }

  public static class TestProcessor implements PostAuthenticationProcessor {

    @Getter
    private int invoked = 0;

    @Override
    public void process(final Saml2UserAuthentication token) throws Saml2ErrorStatusException {
      this.invoked++;
    }

  }

}
