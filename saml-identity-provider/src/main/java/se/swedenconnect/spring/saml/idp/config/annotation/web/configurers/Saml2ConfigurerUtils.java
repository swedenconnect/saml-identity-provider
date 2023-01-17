/*
 * Copyright 2022 Sweden Connect
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

import java.util.Map;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

/**
 * Utility methods for the SAML 2 configurers.
 *
 * @author Martin Lindström
 */
class Saml2ConfigurerUtils {

  private Saml2ConfigurerUtils() {
  }

  static IdentityProviderSettings getIdentityProviderSettings(final HttpSecurity httpSecurity) {
    IdentityProviderSettings identityProviderSettings =
        httpSecurity.getSharedObject(IdentityProviderSettings.class);
    if (identityProviderSettings == null) {
      identityProviderSettings = getBean(httpSecurity, IdentityProviderSettings.class);
      httpSecurity.setSharedObject(IdentityProviderSettings.class, identityProviderSettings);
    }
    return identityProviderSettings;
  }

  static <T> T getBean(final HttpSecurity httpSecurity, final Class<T> type) {
    return httpSecurity.getSharedObject(ApplicationContext.class).getBean(type);
  }

  @SuppressWarnings("unchecked")
  static <T> T getBean(final HttpSecurity httpSecurity, final ResolvableType type) {
    final ApplicationContext context = httpSecurity.getSharedObject(ApplicationContext.class);
    final String[] names = context.getBeanNamesForType(type);
    if (names.length == 1) {
      return (T) context.getBean(names[0]);
    }
    if (names.length > 1) {
      throw new NoUniqueBeanDefinitionException(type, names);
    }
    throw new NoSuchBeanDefinitionException(type);
  }

  static <T> T getOptionalBean(final HttpSecurity httpSecurity, final Class<T> type) {
    final Map<String, T> beansMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(
        httpSecurity.getSharedObject(ApplicationContext.class), type);
    if (beansMap.size() > 1) {
      throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
          "Expected single matching bean of type '" + type.getName() + "' but found " +
              beansMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
    }
    return !beansMap.isEmpty() ? beansMap.values().iterator().next() : null;
  }

  @SuppressWarnings("unchecked")
  static <T> T getOptionalBean(final HttpSecurity httpSecurity, final ResolvableType type) {
    final ApplicationContext context = httpSecurity.getSharedObject(ApplicationContext.class);
    final String[] names = context.getBeanNamesForType(type);
    if (names.length > 1) {
      throw new NoUniqueBeanDefinitionException(type, names);
    }
    return names.length == 1 ? (T) context.getBean(names[0]) : null;
  }

}
