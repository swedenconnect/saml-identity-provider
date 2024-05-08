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
package se.swedenconnect.spring.saml.idp.config;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.annotation.AnnotationBeanNameGenerator;

/**
 * Registers bean definitions on container initialization, if not already present.
 */
final class RegisterMissingBeanPostProcessor implements BeanDefinitionRegistryPostProcessor, BeanFactoryAware {
  private final AnnotationBeanNameGenerator beanNameGenerator = new AnnotationBeanNameGenerator();
  private final List<AbstractBeanDefinition> beanDefinitions = new ArrayList<>();
  private BeanFactory beanFactory;

  @Override
  public void postProcessBeanDefinitionRegistry(final BeanDefinitionRegistry registry) throws BeansException {
    for (final AbstractBeanDefinition beanDefinition : this.beanDefinitions) {
      final String[] beanNames = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(
          (ListableBeanFactory) this.beanFactory, beanDefinition.getBeanClass(), false, false);
      if (beanNames.length == 0) {
        final String beanName = this.beanNameGenerator.generateBeanName(beanDefinition, registry);
        registry.registerBeanDefinition(beanName, beanDefinition);
      }
    }
  }

  @Override
  public void postProcessBeanFactory(final ConfigurableListableBeanFactory beanFactory) throws BeansException {
  }

  <T> void addBeanDefinition(final Class<T> beanClass, final Supplier<T> beanSupplier) {
    this.beanDefinitions.add(new RootBeanDefinition(beanClass, beanSupplier));
  }

  @Override
  public void setBeanFactory(final BeanFactory beanFactory) throws BeansException {
    this.beanFactory = beanFactory;
  }

}
