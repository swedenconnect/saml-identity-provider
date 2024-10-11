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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.opensaml.storage.ReplayCache;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.MessageSource;
import org.springframework.core.ResolvableType;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import se.swedenconnect.opensaml.saml2.response.replay.InMemoryReplayChecker;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayCheckerImpl;
import se.swedenconnect.opensaml.sweid.saml2.signservice.SADFactory;
import se.swedenconnect.opensaml.xmlsec.config.DefaultSecurityConfiguration;
import se.swedenconnect.opensaml.xmlsec.config.SecurityConfiguration;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.spring.saml.idp.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.events.Saml2IdpEventPublisher;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseBuilder;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseSender;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;

/**
 * Utility methods for the SAML 2 configurers.
 *
 * @author Martin Lindström
 */
class Saml2IdpConfigurerUtils {

  private Saml2IdpConfigurerUtils() {
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

  /**
   * Gets the {@link RequestMatcher} for the IdP authentication endpoints
   *
   * @param httpSecurity the HTTP security object
   * @return a {@link RequestMatcher}
   */
  static RequestMatcher getAuthnEndpointsRequestMatcher(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings settings = Saml2IdpConfigurerUtils.getIdentityProviderSettings(httpSecurity);
    final RequestMatcher requestMatcher = new OrRequestMatcher(
        new AntPathRequestMatcher(settings.getEndpoints().getRedirectAuthnEndpoint(), HttpMethod.GET.name()),
        new AntPathRequestMatcher(settings.getEndpoints().getPostAuthnEndpoint(), HttpMethod.POST.name()));
    // TODO: HoK endpoints
    return requestMatcher;
  }

  /**
   * Gets the {@link Saml2IdpEventPublisher} to use.
   *
   * @param httpSecurity the HTTP security object
   * @return a {@link Saml2IdpEventPublisher}
   */
  static Saml2IdpEventPublisher getEventPublisher(final HttpSecurity httpSecurity) {
    Saml2IdpEventPublisher publisher = httpSecurity.getSharedObject(Saml2IdpEventPublisher.class);
    if (publisher != null) {
      return publisher;
    }
    publisher = getOptionalBean(httpSecurity, Saml2IdpEventPublisher.class);
    if (publisher == null) {
      final ApplicationEventPublisher applicationEventPublisher =
          httpSecurity.getSharedObject(ApplicationContext.class);
      publisher = new Saml2IdpEventPublisher(applicationEventPublisher);
    }
    httpSecurity.setSharedObject(Saml2IdpEventPublisher.class, publisher);
    return publisher;
  }

  /**
   * Gets the {@link Saml2ResponseBuilder} to use. If none has been set, a {@link Saml2ResponseBuilder} is created
   * according to the current {@link IdentityProviderSettings}.
   *
   * @param httpSecurity the HTTP security object
   * @return a {@link Saml2ResponseBuilder}
   */
  static Saml2ResponseBuilder getResponseBuilder(final HttpSecurity httpSecurity) {
    Saml2ResponseBuilder responseBuilder = httpSecurity.getSharedObject(Saml2ResponseBuilder.class);
    if (responseBuilder != null) {
      return responseBuilder;
    }
    responseBuilder = getOptionalBean(httpSecurity, Saml2ResponseBuilder.class);
    if (responseBuilder == null) {
      final IdentityProviderSettings settings = getIdentityProviderSettings(httpSecurity);
      responseBuilder = new Saml2ResponseBuilder(
          settings.getEntityId(), getSignatureCredential(httpSecurity), getEventPublisher(httpSecurity));
      responseBuilder.setEncryptAssertions(settings.getAssertionSettings().getEncryptAssertions());
      final MessageSource messageSource = getOptionalBean(httpSecurity, MessageSource.class);
      if (messageSource != null) {
        responseBuilder.setMessageSource(messageSource);
      }
    }
    httpSecurity.setSharedObject(Saml2ResponseBuilder.class, responseBuilder);
    return responseBuilder;
  }

  /**
   * Gets the {@link Saml2ResponseSender} to use. If none has been set, a {@link Saml2ResponseSender} with default
   * settings is created.
   *
   * @param httpSecurity the HTTP security object
   * @return a {@link Saml2ResponseSender}
   */
  static Saml2ResponseSender getResponseSender(final HttpSecurity httpSecurity) {
    Saml2ResponseSender responseSender = httpSecurity.getSharedObject(Saml2ResponseSender.class);
    if (responseSender != null) {
      return responseSender;
    }
    responseSender = getOptionalBean(httpSecurity, Saml2ResponseSender.class);
    if (responseSender == null) {
      responseSender = new Saml2ResponseSender();
    }
    httpSecurity.setSharedObject(Saml2ResponseSender.class, responseSender);
    return responseSender;
  }

  /**
   * Gets the IdP signature credential (from the {@link IdentityProviderSettings}).
   *
   * @param httpSecurity the HTTP security object
   * @return a {@link PkiCredential}
   */
  static PkiCredential getSignatureCredential(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings settings = getIdentityProviderSettings(httpSecurity);
    return Optional.ofNullable(settings.getCredentials().getSignCredential())
        .orElseGet(() -> Optional.ofNullable(settings.getCredentials().getDefaultCredential())
            .orElseThrow(() -> new SecurityException("No signature credential available")));
  }

  /**
   * Gets the IdP encryption/decryption credential (from the {@link IdentityProviderSettings}).
   *
   * @param httpSecurity the HTTP security object
   * @return a {@link PkiCredential} or {@code null} if none has been configured
   */
  static PkiCredential getEncryptCredential(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings settings = getIdentityProviderSettings(httpSecurity);
    return Optional.ofNullable(settings.getCredentials().getEncryptCredential())
        .orElseGet(() -> settings.getCredentials().getDefaultCredential());
  }

  /**
   * Gets the OpenSAML {@link SecurityConfiguration}. If none is available a default is created.
   *
   * @param httpSecurity the HTTP security object
   * @return a {@link SecurityConfiguration} object
   */
  static SecurityConfiguration getSecurityConfiguration(final HttpSecurity httpSecurity) {
    SecurityConfiguration securityConfiguration =
        httpSecurity.getSharedObject(SecurityConfiguration.class);
    if (securityConfiguration == null) {
      securityConfiguration = new DefaultSecurityConfiguration();
      httpSecurity.setSharedObject(SecurityConfiguration.class, securityConfiguration);
    }
    return securityConfiguration;
  }

  /**
   * Gets all {@link UserAuthenticationProvider} instances available
   *
   * @param httpSecurity the HTTP security object
   * @return a (possibly empty) collection of {@link UserAuthenticationProvider} objects
   */
  static Collection<UserAuthenticationProvider> getSaml2UserAuthenticationProviders(
      final HttpSecurity httpSecurity) {
    return getOptionalBeans(httpSecurity, UserAuthenticationProvider.class);
  }

  /**
   * Gets the {@link MessageReplayChecker}.
   *
   * @param httpSecurity the HTTP security object
   * @return a {@link MessageReplayChecker}
   */
  static MessageReplayChecker getMessageReplayChecker(final HttpSecurity httpSecurity) {
    MessageReplayChecker checker = httpSecurity.getSharedObject(MessageReplayChecker.class);
    if (checker != null) {
      return checker;
    }
    checker = getOptionalBean(httpSecurity, MessageReplayChecker.class);
    if (checker == null) {
      final ReplayCache replayCache = getOptionalBean(httpSecurity, ReplayCache.class);
      if (replayCache != null) {
        checker = new MessageReplayCheckerImpl(replayCache, "idp-replay-checker");
      }
    }
    if (checker == null) {
      checker = new InMemoryReplayChecker();
    }
    httpSecurity.setSharedObject(MessageReplayChecker.class, checker);

    return checker;
  }

  /**
   * Gets the {@link SslBundles} bean
   *
   * @param httpSecurity the HTTP security object
   * @return a {@link SslBundles} bean or {@code null} if not available
   */
  @Nullable
  static SslBundles getSslBundles(@Nonnull final HttpSecurity httpSecurity) {
    SslBundles bundles = httpSecurity.getSharedObject(SslBundles.class);
    if (bundles != null) {
      return bundles;
    }
    bundles = getOptionalBean(httpSecurity, SslBundles.class);
    if (bundles != null) {
      httpSecurity.setSharedObject(SslBundles.class, bundles);
    }
    return bundles;
  }

  static <T> T getBean(final HttpSecurity httpSecurity, final Class<T> type) {
    return httpSecurity.getSharedObject(ApplicationContext.class).getBean(type);
  }

  /**
   * Gets the {@link SADFactory} instance to use. If not available as a bean or shared object, the instance is created
   * with default settings.
   *
   * @param httpSecurity the HTTP security object
   * @return a {@link SADFactory} instance
   */
  static SADFactory getSadFactory(final HttpSecurity httpSecurity) {
    SADFactory sadFactory = httpSecurity.getSharedObject(SADFactory.class);
    if (sadFactory != null) {
      return sadFactory;
    }
    sadFactory = getOptionalBean(httpSecurity, SADFactory.class);
    if (sadFactory == null) {
      final IdentityProviderSettings settings = getIdentityProviderSettings(httpSecurity);
      sadFactory = new SADFactory(settings.getEntityId(),
          new OpenSamlCredential(getSignatureCredential(httpSecurity)));
    }
    httpSecurity.setSharedObject(SADFactory.class, sadFactory);
    return sadFactory;
  }

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

  static <T> Collection<T> getOptionalBeans(final HttpSecurity httpSecurity, final Class<T> type) {
    final Map<String, T> beansMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(
        httpSecurity.getSharedObject(ApplicationContext.class), type);
    return beansMap.values();
  }

  static <T> T getOptionalBean(final HttpSecurity httpSecurity, final ResolvableType type) {
    final ApplicationContext context = httpSecurity.getSharedObject(ApplicationContext.class);
    final String[] names = context.getBeanNamesForType(type);
    if (names.length > 1) {
      throw new NoUniqueBeanDefinitionException(type, names);
    }
    return names.length == 1 ? (T) context.getBean(names[0]) : null;
  }

}
