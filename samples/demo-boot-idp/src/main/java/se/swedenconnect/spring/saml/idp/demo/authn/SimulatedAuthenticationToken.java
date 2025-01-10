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
package se.swedenconnect.spring.saml.idp.demo.authn;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import se.swedenconnect.spring.saml.idp.demo.user.SimulatedUser;

import java.io.Serial;
import java.util.Collections;

/**
 * An {@link Authentication} token for our simulated authentication process.
 *
 * @author Martin Lindström
 */
public class SimulatedAuthenticationToken extends AbstractAuthenticationToken {

  @Serial
  private static final long serialVersionUID = -4646659410285834357L;

  /**
   * Constructor.
   *
   * @param user the simulated user (i.e., the user that was authenticated)
   */
  public SimulatedAuthenticationToken(final SimulatedUser user) {
    super(Collections.emptyList());
    this.setDetails(user);
    this.setAuthenticated(true);
  }

  /**
   * Returns {@code null}.
   */
  @Override
  public Object getCredentials() {
    return null;
  }

  /**
   * Returns the {@link SimulatedUser}.
   */
  @Override
  public Object getPrincipal() {
    return this.getDetails();
  }

}
