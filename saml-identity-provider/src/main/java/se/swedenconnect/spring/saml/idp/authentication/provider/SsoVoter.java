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

import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;

/**
 * An interface used by {@link AbstractSaml2UserAuthenticationProvider} to check if an {@link Authentication} object
 * from a previous authentication may be used for SSO.
 * 
 * @author Martin Lindström
 */
public interface SsoVoter {

  public enum Vote {
    OK, DENY, DONT_KNOW;
  }

  /**
   * Predicate that tells whether the supplied {@link Authentication} object may be used in SSO (according to the
   * voter's logic).
   * 
   * @param userAuthn the user authentication object
   * @param token the authentication input token (for the current authentication)
   * @return {@link Vote#OK} if the voter is OK with re-using the authentication, {@link Vote#DENY} if the voter states
   *           that the authentication may noy be re-used, and {@link Vote#DONT_KNOW} if the voter don't know
   */
  Vote mayReuse(final Saml2UserAuthentication userAuthn, final Saml2UserAuthenticationInputToken token);

}
