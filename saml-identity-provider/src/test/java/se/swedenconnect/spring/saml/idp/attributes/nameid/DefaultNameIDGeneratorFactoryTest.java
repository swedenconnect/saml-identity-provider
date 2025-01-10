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
package se.swedenconnect.spring.saml.idp.attributes.nameid;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;

import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

/**
 * Test cases for DefaultNameIDGeneratorFactory.
 *
 * @author Martin Lindström
 */
public class DefaultNameIDGeneratorFactoryTest extends OpenSamlTestBase {

  private static final String IDP = "https://idp.example.com";
  private static final String SP = "https://sp.example.com";

  @Test
  public void testNoIdpEntityId() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new DefaultNameIDGeneratorFactory(null);
    });

    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new DefaultNameIDGeneratorFactory(" ");
    });
  }

  @Test
  public void testFormats() {
    final DefaultNameIDGeneratorFactory f = new DefaultNameIDGeneratorFactory(IDP);
    Assertions.assertEquals(List.of(NameID.PERSISTENT, NameID.TRANSIENT), f.getSupportedFormats());
    Assertions.assertTrue(f.isSupported(NameID.PERSISTENT));
    Assertions.assertTrue(f.isSupported(NameID.TRANSIENT));
    Assertions.assertFalse(f.isSupported("Format"));

    final DefaultNameIDGeneratorFactory f2 = new DefaultNameIDGeneratorFactory(IDP);
    f2.setDefaultFormat(NameID.TRANSIENT);
    Assertions.assertEquals(List.of(NameID.TRANSIENT, NameID.PERSISTENT), f2.getSupportedFormats());
  }

  @Test
  public void testInvalidFormat() {
    final DefaultNameIDGeneratorFactory f = new DefaultNameIDGeneratorFactory(IDP);
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      f.setDefaultFormat("NOT-A-VALID-FORMAT");
    });
  }

  @Test
  public void testGenerateNoSpecify() {
    final AuthnRequest authnReuest = Mockito.mock(AuthnRequest.class);
    Mockito.when(authnReuest.getNameIDPolicy()).thenReturn(null);

    final SPSSODescriptor sso = Mockito.mock(SPSSODescriptor.class);
    Mockito.when(sso.getNameIDFormats()).thenReturn(Collections.emptyList());

    final EntityDescriptor entityDescriptor = Mockito.mock(EntityDescriptor.class);
    Mockito.when(entityDescriptor.getEntityID()).thenReturn(SP);
    Mockito.when(entityDescriptor.getSPSSODescriptor(Mockito.anyString())).thenReturn(sso);

    final DefaultNameIDGeneratorFactory f = new DefaultNameIDGeneratorFactory(IDP);
    final NameIDGenerator generator = f.getNameIDGenerator(authnReuest, entityDescriptor);
    Assertions.assertTrue(generator instanceof PersistentNameIDGenerator);

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getLogString()).thenReturn("logString");

    final Saml2UserAuthentication auth = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(auth.getName()).thenReturn("username");
    Mockito.when(auth.getAuthnRequestToken()).thenReturn(token);

    final NameID nameId = generator.getNameID(auth);
    Assertions.assertEquals(NameID.PERSISTENT, nameId.getFormat());
    Assertions.assertNotNull(nameId.getValue());
    Assertions.assertEquals(IDP, nameId.getNameQualifier());
    Assertions.assertEquals(SP, nameId.getSPNameQualifier());
  }

  @Test
  public void testGenerateNoSpecifyTransient() {
    final AuthnRequest authnReuest = Mockito.mock(AuthnRequest.class);
    Mockito.when(authnReuest.getNameIDPolicy()).thenReturn(null);

    final SPSSODescriptor sso = Mockito.mock(SPSSODescriptor.class);
    Mockito.when(sso.getNameIDFormats()).thenReturn(Collections.emptyList());

    final EntityDescriptor entityDescriptor = Mockito.mock(EntityDescriptor.class);
    Mockito.when(entityDescriptor.getEntityID()).thenReturn(SP);
    Mockito.when(entityDescriptor.getSPSSODescriptor(Mockito.anyString())).thenReturn(sso);

    final DefaultNameIDGeneratorFactory f = new DefaultNameIDGeneratorFactory(IDP);
    f.setDefaultFormat(NameID.TRANSIENT);
    final NameIDGenerator generator = f.getNameIDGenerator(authnReuest, entityDescriptor);
    Assertions.assertTrue(generator instanceof TransientNameIDGenerator);

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getLogString()).thenReturn("logString");

    final Saml2UserAuthentication auth = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(auth.getAuthnRequestToken()).thenReturn(token);

    final NameID nameId = generator.getNameID(auth);
    Assertions.assertEquals(NameID.TRANSIENT, nameId.getFormat());
    Assertions.assertNotNull(nameId.getValue());
    Assertions.assertEquals(IDP, nameId.getNameQualifier());
    Assertions.assertEquals(SP, nameId.getSPNameQualifier());
  }

  @Test
  public void testGenerateNoSpecifyUnspecifiedButOtherSpQualifier() {
    final AuthnRequest authnReuest = Mockito.mock(AuthnRequest.class);

    final NameIDPolicy policy = Mockito.mock(NameIDPolicy.class);
    Mockito.when(policy.getFormat()).thenReturn(NameID.UNSPECIFIED);
    Mockito.when(policy.getSPNameQualifier()).thenReturn("https://other.sp.example.com");

    Mockito.when(authnReuest.getNameIDPolicy()).thenReturn(policy);

    final SPSSODescriptor sso = Mockito.mock(SPSSODescriptor.class);
    Mockito.when(sso.getNameIDFormats()).thenReturn(Collections.emptyList());

    final EntityDescriptor entityDescriptor = Mockito.mock(EntityDescriptor.class);
    Mockito.when(entityDescriptor.getEntityID()).thenReturn(SP);
    Mockito.when(entityDescriptor.getSPSSODescriptor(Mockito.anyString())).thenReturn(sso);

    final DefaultNameIDGeneratorFactory f = new DefaultNameIDGeneratorFactory(IDP);
    final NameIDGenerator generator = f.getNameIDGenerator(authnReuest, entityDescriptor);
    Assertions.assertTrue(generator instanceof PersistentNameIDGenerator);

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getLogString()).thenReturn("logString");

    final Saml2UserAuthentication auth = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(auth.getName()).thenReturn("username");
    Mockito.when(auth.getAuthnRequestToken()).thenReturn(token);

    final NameID nameId = generator.getNameID(auth);
    Assertions.assertEquals(NameID.PERSISTENT, nameId.getFormat());
    Assertions.assertNotNull(nameId.getValue());
    Assertions.assertEquals(IDP, nameId.getNameQualifier());
    Assertions.assertEquals("https://other.sp.example.com", nameId.getSPNameQualifier());
  }

  @Test
  public void testGenerateAuthnRequestSpecifiesTransient() {
    final AuthnRequest authnReuest = Mockito.mock(AuthnRequest.class);

    final NameIDPolicy policy = Mockito.mock(NameIDPolicy.class);
    Mockito.when(policy.getFormat()).thenReturn(NameID.TRANSIENT);
    Mockito.when(policy.getSPNameQualifier()).thenReturn(null);

    Mockito.when(authnReuest.getNameIDPolicy()).thenReturn(policy);

    final SPSSODescriptor sso = Mockito.mock(SPSSODescriptor.class);
    Mockito.when(sso.getNameIDFormats()).thenReturn(Collections.emptyList());

    final EntityDescriptor entityDescriptor = Mockito.mock(EntityDescriptor.class);
    Mockito.when(entityDescriptor.getEntityID()).thenReturn(SP);
    Mockito.when(entityDescriptor.getSPSSODescriptor(Mockito.anyString())).thenReturn(sso);

    final DefaultNameIDGeneratorFactory f = new DefaultNameIDGeneratorFactory(IDP);
    f.setDefaultFormat(NameID.PERSISTENT);

    final NameIDGenerator generator = f.getNameIDGenerator(authnReuest, entityDescriptor);
    Assertions.assertTrue(generator instanceof TransientNameIDGenerator);

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getLogString()).thenReturn("logString");

    final Saml2UserAuthentication auth = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(auth.getName()).thenReturn("username");
    Mockito.when(auth.getAuthnRequestToken()).thenReturn(token);

    final NameID nameId = generator.getNameID(auth);
    Assertions.assertEquals(NameID.TRANSIENT, nameId.getFormat());
    Assertions.assertNotNull(nameId.getValue());
    Assertions.assertEquals(IDP, nameId.getNameQualifier());
    Assertions.assertEquals(SP, nameId.getSPNameQualifier());
  }

  @Test
  public void testGenerateAuthnRequestSpecifiesInvalidFormat() {
    final AuthnRequest authnReuest = Mockito.mock(AuthnRequest.class);

    final NameIDPolicy policy = Mockito.mock(NameIDPolicy.class);
    Mockito.when(policy.getFormat()).thenReturn("Bad");
    Mockito.when(policy.getSPNameQualifier()).thenReturn(null);

    Mockito.when(authnReuest.getNameIDPolicy()).thenReturn(policy);

    final SPSSODescriptor sso = Mockito.mock(SPSSODescriptor.class);
    Mockito.when(sso.getNameIDFormats()).thenReturn(Collections.emptyList());

    final EntityDescriptor entityDescriptor = Mockito.mock(EntityDescriptor.class);
    Mockito.when(entityDescriptor.getEntityID()).thenReturn(SP);
    Mockito.when(entityDescriptor.getSPSSODescriptor(Mockito.anyString())).thenReturn(sso);

    final DefaultNameIDGeneratorFactory f = new DefaultNameIDGeneratorFactory(IDP);

    final Status status = Assertions.assertThrows(Saml2ErrorStatusException.class, () -> {
      f.getNameIDGenerator(authnReuest, entityDescriptor);
    }).getStatus();
    Assertions.assertEquals(StatusCode.INVALID_NAMEID_POLICY, status.getStatusCode().getStatusCode().getValue());
  }

  @Test
  public void testGenerateMetadataSpecifiesTransient() {
    final AuthnRequest authnReuest = Mockito.mock(AuthnRequest.class);
    Mockito.when(authnReuest.getNameIDPolicy()).thenReturn(null);

    final SPSSODescriptor sso = Mockito.mock(SPSSODescriptor.class);
    final NameIDFormat f1 = Mockito.mock(NameIDFormat.class);
    Mockito.when(f1.getURI()).thenReturn(NameID.TRANSIENT);
    final NameIDFormat f2 = Mockito.mock(NameIDFormat.class);
    Mockito.when(f2.getURI()).thenReturn(NameID.PERSISTENT);
    Mockito.when(sso.getNameIDFormats()).thenReturn(List.of(f1, f2));

    final EntityDescriptor entityDescriptor = Mockito.mock(EntityDescriptor.class);
    Mockito.when(entityDescriptor.getEntityID()).thenReturn(SP);
    Mockito.when(entityDescriptor.getSPSSODescriptor(Mockito.anyString())).thenReturn(sso);

    final DefaultNameIDGeneratorFactory f = new DefaultNameIDGeneratorFactory(IDP);
    f.setDefaultFormat(NameID.PERSISTENT);

    final NameIDGenerator generator = f.getNameIDGenerator(authnReuest, entityDescriptor);
    Assertions.assertTrue(generator instanceof TransientNameIDGenerator);

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getLogString()).thenReturn("logString");

    final Saml2UserAuthentication auth = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(auth.getName()).thenReturn("username");
    Mockito.when(auth.getAuthnRequestToken()).thenReturn(token);

    final NameID nameId = generator.getNameID(auth);
    Assertions.assertEquals(NameID.TRANSIENT, nameId.getFormat());
    Assertions.assertNotNull(nameId.getValue());
    Assertions.assertEquals(IDP, nameId.getNameQualifier());
    Assertions.assertEquals(SP, nameId.getSPNameQualifier());
  }

  @Test
  public void testGenerateMetadataSpecifiesPersistent() {
    final AuthnRequest authnReuest = Mockito.mock(AuthnRequest.class);
    Mockito.when(authnReuest.getNameIDPolicy()).thenReturn(null);

    final SPSSODescriptor sso = Mockito.mock(SPSSODescriptor.class);
    final NameIDFormat f0 = Mockito.mock(NameIDFormat.class);
    Mockito.when(f0.getURI()).thenReturn(NameID.KERBEROS);
    final NameIDFormat f1 = Mockito.mock(NameIDFormat.class);
    Mockito.when(f1.getURI()).thenReturn(NameID.TRANSIENT);
    final NameIDFormat f2 = Mockito.mock(NameIDFormat.class);
    Mockito.when(f2.getURI()).thenReturn(NameID.PERSISTENT);
    Mockito.when(sso.getNameIDFormats()).thenReturn(List.of(f0, f2, f1));

    final EntityDescriptor entityDescriptor = Mockito.mock(EntityDescriptor.class);
    Mockito.when(entityDescriptor.getEntityID()).thenReturn(SP);
    Mockito.when(entityDescriptor.getSPSSODescriptor(Mockito.anyString())).thenReturn(sso);

    final DefaultNameIDGeneratorFactory f = new DefaultNameIDGeneratorFactory(IDP);
    f.setDefaultFormat(NameID.PERSISTENT);

    final NameIDGenerator generator = f.getNameIDGenerator(authnReuest, entityDescriptor);
    Assertions.assertTrue(generator instanceof PersistentNameIDGenerator);

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getLogString()).thenReturn(null);

    final Saml2UserAuthentication auth = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(auth.getName()).thenReturn("username");
    Mockito.when(auth.getAuthnRequestToken()).thenReturn(token);

    final NameID nameId = generator.getNameID(auth);
    Assertions.assertEquals(NameID.PERSISTENT, nameId.getFormat());
    Assertions.assertNotNull(nameId.getValue());
    Assertions.assertEquals(IDP, nameId.getNameQualifier());
    Assertions.assertEquals(SP, nameId.getSPNameQualifier());
  }

}
