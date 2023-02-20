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

import org.opensaml.saml.saml2.core.Assertion;

import se.swedenconnect.spring.saml.idp.attributes.AttributeProducer;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

/**
 * Handler responsible of building SAML {@link Assertion}s given {@link Saml2UserAuthentication} objects.
 * 
 * @author Martin Lindström
 */
public interface Saml2AssertionHandler {

  /**
   * Given a {@link Saml2UserAuthentication} object a SAML {@link Assertion} is built.
   * 
   * @param userAuthentication the information about the user authentication
   * @param attributeProducer decides which attributes from the user token that should be released in the assertion
   * @return an {@link Assertion}
   * @throws Saml2ErrorStatusException for errors that should be reported back to the Service Provider
   * @throws UnrecoverableSaml2IdpException for unrecoverable errors
   */
  Assertion buildAssertion(final Saml2UserAuthentication userAuthentication, final AttributeProducer attributeProducer)
      throws Saml2ErrorStatusException, UnrecoverableSaml2IdpException;

}
