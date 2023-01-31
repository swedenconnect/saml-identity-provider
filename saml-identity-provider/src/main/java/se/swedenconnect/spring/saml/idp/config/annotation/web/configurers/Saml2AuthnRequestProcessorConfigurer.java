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

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

/**
 * A configurer for the processing of SAML2 {@code AuthnRequest} messages.
 */
public class Saml2AuthnRequestProcessorConfigurer extends AbstractSaml2Configurer {

  private RequestMatcher requestMatcher;
  private final List<AuthenticationConverter> authnRequestConverters = new ArrayList<>();

  Saml2AuthnRequestProcessorConfigurer(final ObjectPostProcessor<Object> objectPostProcessor) {
    super(objectPostProcessor);
  }

  @Override
  void init(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings settings = Saml2ConfigurerUtils.getIdentityProviderSettings(httpSecurity);
    this.requestMatcher = new OrRequestMatcher(
        new AntPathRequestMatcher(settings.getEndpoints().getRedirectAuthnEndpoint(), HttpMethod.GET.name()),
        new AntPathRequestMatcher(settings.getEndpoints().getPostAuthnEndpoint(), HttpMethod.POST.name()));
    // TODO: HoK endpoints
  }

  @Override
  void configure(final HttpSecurity httpSecurity) {
  }

  /** {@inheritDoc} */
  @Override
  RequestMatcher getRequestMatcher() {
    return this.requestMatcher;
  }

}
