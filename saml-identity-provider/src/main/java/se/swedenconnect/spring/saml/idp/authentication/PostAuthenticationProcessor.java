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
package se.swedenconnect.spring.saml.idp.authentication;

import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

/**
 * After the user authentication a {@link Saml2UserAuthentication} token is received. Before this token is translated
 * into a SAML assertion it is fed to the {@link PostAuthenticationProcessor} that asserts that the authentication
 * process delivered what was expected (and needed).
 * <p>
 * Note: The processor may also modify the {@link Saml2UserAuthentication} token and not only check it.
 * </p>
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface PostAuthenticationProcessor {

  /**
   * Applies post-processing of a {@link Saml2UserAuthentication} token.
   *
   * @param token the token to process
   * @throws Saml2ErrorStatusException if an error is detected
   */
  void process(final Saml2UserAuthentication token) throws Saml2ErrorStatusException;

}
