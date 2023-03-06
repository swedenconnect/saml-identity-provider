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
package se.swedenconnect.spring.saml.idp.demo.authn;

import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import se.swedenconnect.spring.saml.idp.demo.SimulatedUser;

public class SimulatedAuthentication extends AbstractAuthenticationToken {

  private static final long serialVersionUID = -4646659410285834357L;

  public SimulatedAuthentication(final SimulatedUser user) {
    super(Collections.emptyList());
    this.setDetails(user);
    this.setAuthenticated(true);
  }

  @Override
  public Object getCredentials() {
    return null;
  }

  @Override
  public Object getPrincipal() {
    return this.getDetails();
  }

}
