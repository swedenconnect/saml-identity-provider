/*
 * Copyright 2023-2026 Sweden Connect
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
package se.swedenconnect.spring.saml.idp.authnrequest.authncontext;

import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import se.swedenconnect.opensaml.saml2.core.build.RequestedAuthnContextBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for AuthnContextResolver.
 *
 * @author Martin Lindström
 */
class AuthnContextResolverTest extends OpenSamlTestBase {

  /**
   * Tests that when a null RequestedAuthnContext is provided, the resolver returns an empty list.
   */
  @Test
  void testResolveWithNullRequestedAuthnContext() throws Saml2ErrorStatusException {
    final AuthnContextResolver resolver = new AuthnContextResolver();
    final List<String> result = resolver.resolve(null, "testLogString");
    assertTrue(result.isEmpty());
  }

  /**
   * Tests that the resolver returns the requested URIs for EXACT or null comparison.
   */
  @Test
  void testResolveExactComparison() throws Saml2ErrorStatusException {
    final AuthnContextResolver resolver = new AuthnContextResolver();

    final RequestedAuthnContext requestedAuthnContext = RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.EXACT)
        .authnContextClassRefs("uri1", "uri2")
        .build();

    final List<String> result = resolver.resolve(requestedAuthnContext, "testLogString");
    assertEquals(Arrays.asList("uri1", "uri2"), result);
  }

  /**
   * Tests that the resolver throws an exception when AuthnContextDeclRefs are provided without AuthnContextClassRefs.
   */
  @Test
  void testResolveWithDeclRefOnly() {
    final AuthnContextResolver resolver = new AuthnContextResolver();

    final RequestedAuthnContext requestedAuthnContext = RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.EXACT)
        .authnContextDeclRefs("uri1", "uri2")
        .build();

    final Saml2ErrorStatusException exception = assertThrows(Saml2ErrorStatusException.class, () ->
        resolver.resolve(requestedAuthnContext, "testLogString")
    );
    assertEquals("Invalid AuthnRequest - AuthnContextDeclRefs not supported in RequestedAuthnContext",
        exception.getMessage());
  }

  /**
   * Tests that the resolver handles MINIMUM comparison with valid mappings.
   */
  @Test
  void testResolveMinComparisonWithMappings() throws Saml2ErrorStatusException {
    final AuthnContextResolver resolver = new AuthnContextResolver();

    final Map<String, List<String>> minimumMapping = new HashMap<>();
    minimumMapping.put(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2,
        List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3,
            LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4));
    minimumMapping.put(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3,
        List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4));
    minimumMapping.put(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4,
        List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4));

    minimumMapping.put(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA2,
        List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3,
            LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA2,
            LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA3));

    minimumMapping.put(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA3,
        List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4,
            LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA3));

    resolver.setMinimumMapping(minimumMapping);

    // Plain LoA2 -> LoA2, LoA3, LoA4
    //
    RequestedAuthnContext requestedAuthnContext = RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.MINIMUM)
        .authnContextClassRefs(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2)
        .build();
    List<String> result = resolver.resolve(requestedAuthnContext, "testLogString");

    assertEquals(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3,
        LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4), result);

    // Plain LoA3 -> LoA3, LoA4
    //
    requestedAuthnContext = RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.MINIMUM)
        .authnContextClassRefs(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)
        .build();
    result = resolver.resolve(requestedAuthnContext, "testLogString");

    assertEquals(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4),
        result);

    // LoA2 Uncertified -> LoA2, LoA3, LoA4, LoA2 Uncertified, LoA3 Uncertified
    requestedAuthnContext = RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.MINIMUM)
        .authnContextClassRefs(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA2)
        .build();
    result = resolver.resolve(requestedAuthnContext, "testLogString");

    assertEquals(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3,
            LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA2,
            LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA3),
        result);
  }

  /**
   * Tests that the resolver throws an exception for MINIMUM comparison without mappings.
   */
  @Test
  void testResolveMinComparisonWithoutMappings() {
    final AuthnContextResolver resolver = new AuthnContextResolver();

    final RequestedAuthnContext requestedAuthnContext = RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.MINIMUM)
        .authnContextClassRefs(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2)
        .build();

    final Saml2ErrorStatusException exception = assertThrows(Saml2ErrorStatusException.class, () ->
        resolver.resolve(requestedAuthnContext, "testLogString")
    );

    assertEquals("Invalid AuthnRequest - minimum comparison for RequestedAuthnContext is not supported",
        exception.getMessage());
  }

  /**
   * Tests that the resolver handles BETTER comparison and resolves correct mappings.
   */
  @Test
  void testResolveBetterComparisonWithMappings() throws Saml2ErrorStatusException {
    final AuthnContextResolver resolver = new AuthnContextResolver();

    final Map<String, List<String>> betterMapping = new HashMap<>();
    betterMapping.put(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2,
        List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4));
    betterMapping.put(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3,
        List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4));
    betterMapping.put(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4, Collections.emptyList());
    betterMapping.put(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA2,
        List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA3,
            LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4));
    betterMapping.put(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA3,
        List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4));
    resolver.setBetterMapping(betterMapping);

    // Plain LoA2 -> LoA3, LoA4
    RequestedAuthnContext requestedAuthnContext = RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.BETTER)
        .authnContextClassRefs(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2)
        .build();
    List<String> result = resolver.resolve(requestedAuthnContext, "testLogString");

    assertEquals(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4),
        result);

    // LoA2 and LoA3 -> LoA4
    //
    requestedAuthnContext = RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.BETTER)
        .authnContextClassRefs(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)
        .build();
    result = resolver.resolve(requestedAuthnContext, "testLogString");

    assertEquals(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4), result);

    // LoA2 and LoA2 uncert -> LoA3, LoA4
    //
    requestedAuthnContext = RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.BETTER)
        .authnContextClassRefs(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2,
            LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA2)
        .build();
    result = resolver.resolve(requestedAuthnContext, "testLogString");

    assertEquals(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4),
        result);

    // LoA4 -> error
    //
    final RequestedAuthnContext rac = RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.BETTER)
        .authnContextClassRefs(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4)
        .build();

    final Saml2ErrorStatusException exception = assertThrows(Saml2ErrorStatusException.class, () ->
        resolver.resolve(rac, "testLogString")
    );

    assertEquals("Invalid AuthnRequest - no configuration for better comparison URI:s in RequestedAuthnContext",
        exception.getMessage());
  }

  /**
   * Tests that the resolver handles MAXIMUM comparison and resolves correct mappings.
   */
  @Test
  void testResolveMaxComparisonWithMappings() throws Saml2ErrorStatusException {
    final AuthnContextResolver resolver = new AuthnContextResolver();

    final Map<String, List<String>> maximumMapping = new HashMap<>();
    maximumMapping.put(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2, Collections.emptyList());
    maximumMapping.put(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3,
        List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2));
    maximumMapping.put(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4,
        List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3));
    resolver.setMaximumMapping(maximumMapping);

    // LoA4 -> LoA2, LoA3
    //
    RequestedAuthnContext requestedAuthnContext = RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.MAXIMUM)
        .authnContextClassRefs(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4)
        .build();

    List<String> result = resolver.resolve(requestedAuthnContext, "testLogString");

    assertEquals(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3),
        result);

    // LoA4, LoA3 -> LoA2
    //
    requestedAuthnContext = RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.MAXIMUM)
        .authnContextClassRefs(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)
        .build();

    result = resolver.resolve(requestedAuthnContext, "testLogString");

    assertEquals(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2),
        result);

    // LoA2 -> error
    //
    final RequestedAuthnContext rac = RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.MAXIMUM)
        .authnContextClassRefs(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2)
        .build();

    final Saml2ErrorStatusException exception = assertThrows(Saml2ErrorStatusException.class, () ->
        resolver.resolve(rac, "testLogString")
    );

    assertEquals("Invalid AuthnRequest - no configuration for maximum comparison URI:s in RequestedAuthnContext",
        exception.getMessage());

  }

  @Test
  void testResolveMaximimComparisonWithoutMappings() {
    final AuthnContextResolver resolver = new AuthnContextResolver();

    final RequestedAuthnContext requestedAuthnContext = RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.MAXIMUM)
        .authnContextClassRefs(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2)
        .build();

    final Saml2ErrorStatusException exception = assertThrows(Saml2ErrorStatusException.class, () ->
        resolver.resolve(requestedAuthnContext, "testLogString")
    );

    assertEquals("Invalid AuthnRequest - maximum comparison for RequestedAuthnContext is not supported",
        exception.getMessage());
  }

}
