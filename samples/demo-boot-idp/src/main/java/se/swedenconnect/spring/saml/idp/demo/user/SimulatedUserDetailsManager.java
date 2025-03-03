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
package se.swedenconnect.spring.saml.idp.demo.user;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * An {@link UserDetailsManager} implementation for simulated users.
 *
 * @author Martin Lindström
 */
public class SimulatedUserDetailsManager implements UserDetailsManager {

  private final Map<String, SimulatedUser> users = new HashMap<>();

  @Override
  public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
    return Optional.ofNullable(this.users.get(username))
        .orElseThrow(() -> new UsernameNotFoundException(username));
  }

  @Override
  public void createUser(final UserDetails user) {
    if (!(user instanceof SimulatedUser)) {
      throw new IllegalArgumentException("Expected " + SimulatedUser.class.getSimpleName());
    }
    this.users.put(user.getUsername(), (SimulatedUser) user);
  }

  @Override
  public void updateUser(final UserDetails user) {
    if (!this.userExists(user.getUsername())) {
      throw new IllegalArgumentException("User does not exist");
    }
    this.createUser(user);
  }

  @Override
  public void deleteUser(final String username) {
    this.users.remove(username);
  }

  @Override
  public void changePassword(final String oldPassword, final String newPassword) {
  }

  @Override
  public boolean userExists(final String username) {
    return this.users.containsKey(username);
  }

}
