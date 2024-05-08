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
package se.swedenconnect.spring.saml.idp.authentication;

import java.util.List;

import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

/**
 * A delegating {@link PostAuthenticationProcessor} that invokes
 * {@link PostAuthenticationProcessor#process(Saml2UserAuthentication)} on all configured processors (in order).
 * 
 * @author Martin Lindström
 */
public class DelegatingPostAuthenticationProcessor implements PostAuthenticationProcessor {
  
  private final List<PostAuthenticationProcessor> processors;
  
  /**
   * Constructor.
   * 
   * @param processors the processors (may be {@code null} or empty)
   */
  public DelegatingPostAuthenticationProcessor(final List<PostAuthenticationProcessor> processors) {
    this.processors = processors;
  }

  /** {@inheritDoc} */
  @Override
  public void process(final Saml2UserAuthentication token) throws Saml2ErrorStatusException {
    if (this.processors != null) {
      this.processors.forEach(p -> p.process(token));
    }
  }

}
