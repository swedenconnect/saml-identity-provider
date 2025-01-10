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
package se.swedenconnect.spring.saml.idp.autoconfigure.audit;

import java.util.function.Predicate;

import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.AuditEventRepository;

import se.swedenconnect.spring.saml.idp.audit.repository.AuditEventMapper;

/**
 * For creating Redis {@link AuditEventRepository} beans.
 */
@FunctionalInterface
public interface AuditEventRepositoryFactory {

  /**
   * Creates an {@link AuditEventRepository}.
   *
   * @param name the Redis name for the list/timeseries
   * @param auditEventMapper the event mapper
   * @param filter the filter predicate
   * @return an {@link AuditEventRepository}
   */
  AuditEventRepository create(
      final String name, final AuditEventMapper auditEventMapper, Predicate<AuditEvent> filter);

}
