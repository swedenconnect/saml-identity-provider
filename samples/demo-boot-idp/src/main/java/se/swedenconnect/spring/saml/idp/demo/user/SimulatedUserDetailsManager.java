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
package se.swedenconnect.spring.saml.idp.demo.user;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;

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
  public void createUser(UserDetails user) {
    if (!SimulatedUser.class.isInstance(user)) {
      throw new IllegalArgumentException("Expected " + SimulatedUser.class.getSimpleName());
    }
    this.users.put(user.getUsername(), SimulatedUser.class.cast(user));
  }

  @Override
  public void updateUser(UserDetails user) {
    if (!this.userExists(user.getUsername())) {
      throw new IllegalArgumentException("User does not exist");
    }
    this.createUser(user);
  }

  @Override
  public void deleteUser(String username) {
    this.users.remove(username);
  }

  @Override
  public void changePassword(String oldPassword, String newPassword) {
  }

  @Override
  public boolean userExists(String username) {
    return this.users.containsKey(username);
  }

}
