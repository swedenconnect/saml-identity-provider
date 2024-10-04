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
package se.swedenconnect.spring.saml.idp.attributes.nameid;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

import java.util.List;

/**
 * A {@link NameIDGenerator} is assigned each {@link Saml2AuthnRequestAuthenticationToken} when an {@link AuthnRequest}
 * is being processed. When the user has been authenticated and an {@link Assertion} is created this generator will be
 * used to generate a {@code NameID}.
 *
 * @author Martin Lindström
 */
public interface NameIDGeneratorFactory {

  /**
   * Given the requirements for a {@code NameID} in the {@link AuthnRequest} and {@link EntityDescriptor} along with the
   * IdP policy the method returns a {@link NameIDGenerator}.
   *
   * @param authnRequest the {@link AuthnRequest}
   * @param peerMetadata the peer metadata
   * @return a {@link NameIDGenerator}
   * @throws Saml2ErrorStatusException for errors that should be reported back to the Service Provider
   * @throws UnrecoverableSaml2IdpException for non-recoverable errors
   */
  NameIDGenerator getNameIDGenerator(final AuthnRequest authnRequest, final EntityDescriptor peerMetadata)
      throws Saml2ErrorStatusException, UnrecoverableSaml2IdpException;

  /**
   * Gets a list of the {@code NameIDFormat}s that are supported by the factory. The most preferred should be added
   * first.
   *
   * @return a list of the supported formats
   */
  List<String> getSupportedFormats();

}
