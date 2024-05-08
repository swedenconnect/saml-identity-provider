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
package se.swedenconnect.spring.saml.idp.config.configurers;

import java.io.IOException;
import java.io.Serial;
import java.util.Objects;

import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.context.Saml2IdpContext;
import se.swedenconnect.spring.saml.idp.context.Saml2IdpContextHolder;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseAttributes;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

/**
 * A {@code Filter} that associates the {@link Saml2IdpContext} to the {@link Saml2IdpContextHolder}.
 *
 * @author Martin Lindström
 */
class Saml2IdpContextFilter extends OncePerRequestFilter {

  private final IdentityProviderSettings settings;

  /**
   * Constructor assigning the {@link IdentityProviderSettings}.
   *
   * @param settings the IdP settings
   */
  Saml2IdpContextFilter(final IdentityProviderSettings settings) {
    this.settings = Objects.requireNonNull(settings, "settings must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void doFilterInternal(
      final HttpServletRequest request, final HttpServletResponse response, final FilterChain filterChain)
      throws ServletException, IOException {

    try {
      Saml2IdpContextHolder.setContext(new DefaultIdentityProviderContext(this.settings));
      filterChain.doFilter(request, response);
    }
    finally {
      Saml2IdpContextHolder.resetContext();
    }
  }

  /**
   * Implementation of the {@link Saml2IdpContext}.
   */
  private static class DefaultIdentityProviderContext implements Saml2IdpContext {

    @Serial
    private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

    private final IdentityProviderSettings settings;

    private final Saml2ResponseAttributes responseAttributes;

    /**
     * Constructor.
     *
     * @param settings the IdP settings
     */
    private DefaultIdentityProviderContext(final IdentityProviderSettings settings) {
      this.settings = settings;
      this.responseAttributes = new Saml2ResponseAttributes();
    }

    /** {@inheritDoc} */
    @Override
    public IdentityProviderSettings getSettings() {
      return this.settings;
    }

    /** {@inheritDoc} */
    @Override
    public Saml2ResponseAttributes getResponseAttributes() {
      return this.responseAttributes;
    }

  }

}
