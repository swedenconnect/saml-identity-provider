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
package se.swedenconnect.spring.saml.idp.authnrequest.validation;

import org.opensaml.saml.saml2.core.AuthnRequest;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

/**
 * A genric interface for performing validation of an {@link AuthnRequest}.
 *
 * @author Martin Lindström
 */
public interface AuthnRequestValidator {

  /**
   * Performs validation of a feature/requirement regarding the supplied SAML 2 authentication request.
   * <p>
   * The method may update the supplied token with information useful in later stages.
   * </p>
   *
   * @param authnRequestToken the authentication request token
   * @throws UnrecoverableSaml2IdpException for errors that can not be signalled back to the SAML SP
   * @throws Saml2ErrorStatusException for errors that should be sent as SAML error responses
   */
  void validate(final Saml2AuthnRequestAuthenticationToken authnRequestToken)
      throws UnrecoverableSaml2IdpException, Saml2ErrorStatusException;

}
