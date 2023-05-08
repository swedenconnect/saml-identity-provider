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

import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.Getter;
import lombok.Setter;

/**
 * A simulated user.
 * 
 * @author Martin Lindström
 */
public class SimulatedUser implements UserDetails {

  private static final long serialVersionUID = 6822029385234222613L;

  /**
   * The personal identity number.
   */
  @Getter
  @Setter
  private String personalNumber;

  /**
   * The given name.
   */
  @Getter
  @Setter
  private String givenName;

  /**
   * The surname.
   */
  @Getter
  @Setter
  private String surname;

  /**
   * The display name.
   */
  @Getter
  @Setter
  private String displayName;

  /**
   * The date of birth (YYYY-MM-DD)
   */
  @Getter
  @Setter
  private String dateOfBirth;

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return Collections.emptyList();
  }

  @Override
  public String getPassword() {
    return "";
  }

  @Override
  public String getUsername() {
    return this.personalNumber;
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }
  
  public String toViewString() {
    return String.format("%s (%s)", this.displayName, this.personalNumber);
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.personalNumber);
  }

  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if ((obj == null) || (this.getClass() != obj.getClass())) {
      return false;
    }
    final SimulatedUser other = (SimulatedUser) obj;
    return Objects.equals(this.personalNumber, other.personalNumber);
  }

}
