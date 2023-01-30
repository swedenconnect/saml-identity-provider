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
package se.swedenconnect.spring.saml.idp.config.annotation.web.configurers;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

import se.swedenconnect.spring.saml.idp.context.IdentityProviderContext;
import se.swedenconnect.spring.saml.idp.context.IdentityProviderContextHolder;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

/**
 * A {@code Filter} that associates the {@link IdentityProviderContext} to the {@link IdentityProviderContextHolder}.
 *
 * @author Martin Lindström
 */
class IdentityProviderContextFilter extends OncePerRequestFilter {

  private final IdentityProviderSettings settings;

  /**
   * Constructor assigning the {@link IdentityProviderSettings}.
   *
   * @param settings the IdP settings
   */
  IdentityProviderContextFilter(final IdentityProviderSettings settings) {
    this.settings = Objects.requireNonNull(settings, "settings must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void doFilterInternal(
      final HttpServletRequest request, final HttpServletResponse response, final FilterChain filterChain)
      throws ServletException, IOException {
    try {
      IdentityProviderContextHolder.setContext(new DefaultIdentityProviderContext(this.settings));
      filterChain.doFilter(request, response);
    }
    finally {
      IdentityProviderContextHolder.resetContext();
    }
  }

  private static class DefaultIdentityProviderContext implements IdentityProviderContext {

    private final IdentityProviderSettings settings;

    private DefaultIdentityProviderContext(final IdentityProviderSettings settings) {
      this.settings = settings;
    }

    @Override
    public IdentityProviderSettings getSettings() {
      return this.settings;
    }

  }

}
