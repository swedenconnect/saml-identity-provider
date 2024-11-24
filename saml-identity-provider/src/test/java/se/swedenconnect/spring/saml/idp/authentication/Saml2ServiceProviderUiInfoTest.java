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
package se.swedenconnect.spring.saml.idp.authentication;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.LogoBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.OrganizationBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.UIInfoBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.PrincipalSelectionBuilder;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;

/**
 * Test cases for Saml2ServiceProviderUiInfo.
 *
 * @author Martin Lindström
 */
public class Saml2ServiceProviderUiInfoTest extends OpenSamlTestBase {

  private static final String SP = "https://sp.example.com";

  @Test
  public void testUiEmpty() {
    EntityDescriptor ed = EntityDescriptorBuilder.builder()
        .entityID(SP)
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .build())
        .build();

    Saml2ServiceProviderUiInfo ui = new Saml2ServiceProviderUiInfo(ed);

    Assertions.assertEquals(SP, ui.getEntityId());
    Assertions.assertTrue(ui.getDisplayNames().isEmpty());
    Assertions.assertNull(ui.getDisplayName("sv"));
    Assertions.assertTrue(ui.getDescriptions().isEmpty());
    Assertions.assertNull(ui.getDescription("sv"));
    Assertions.assertTrue(ui.getLogotypes().isEmpty());

    ed = EntityDescriptorBuilder.builder()
        .entityID(SP)
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .extensions(ExtensionsBuilder.builder()
                .extension(PrincipalSelectionBuilder.builder().build())
                .build())
            .build())
        .build();

    ui = new Saml2ServiceProviderUiInfo(ed);

    Assertions.assertEquals(SP, ui.getEntityId());
    Assertions.assertTrue(ui.getDisplayNames().isEmpty());
    Assertions.assertNull(ui.getDisplayName("sv"));
    Assertions.assertTrue(ui.getDescriptions().isEmpty());
    Assertions.assertNull(ui.getDescription("sv"));
    Assertions.assertTrue(ui.getLogotypes().isEmpty());
  }

  @Test
  public void testUi() {
    final EntityDescriptor ed = EntityDescriptorBuilder.builder()
        .entityID(SP)
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .extensions(ExtensionsBuilder.builder()
                .extension(UIInfoBuilder.builder()
                    .displayNames(
                        List.of(new LocalizedString("Display name", "en"), new LocalizedString("Visningsnamn", "sv")))
                    .descriptions(List.of(
                        new LocalizedString("Description", "en"), new LocalizedString("Beskrivning", "sv")))
                    .logos(List.of(
                        LogoBuilder.builder()
                            .height(50)
                            .width(50)
                            .url(SP + "/logo.png")
                            .language("en")
                            .build(),
                        LogoBuilder.builder()
                            .height(150)
                            .width(150)
                            .url(SP + "/logo2.png")
                            .build(),
                        LogoBuilder.builder().build()))
                    .build())
                .build())
            .build())
        .build();

    final Saml2ServiceProviderUiInfo ui = new Saml2ServiceProviderUiInfo(ed);

    Assertions.assertEquals(SP, ui.getEntityId());
    Assertions.assertTrue(ui.getDisplayNames().size() == 2);
    Assertions.assertEquals("Visningsnamn", ui.getDisplayName("sv"));
    Assertions.assertEquals("Display name", ui.getDisplayName("en"));
    Assertions.assertNull(ui.getDisplayName("de"));

    Assertions.assertTrue(ui.getDescriptions().size() == 2);
    Assertions.assertEquals("Beskrivning", ui.getDescription("sv"));
    Assertions.assertEquals("Description", ui.getDescription("en"));
    Assertions.assertNull(ui.getDescription("de"));

    Assertions.assertTrue(ui.getLogotypes().size() == 2);
    Assertions.assertEquals(SP + "/logo2.png", ui.getLogotype((p) -> p.getHeight() > 100).getUrl());
    Assertions.assertEquals("en", ui.getLogotype((p) -> p.getWidth() < 100).getLanguage());
  }

  @Test
  public void testUiAndOrganization() {
    final EntityDescriptor ed = EntityDescriptorBuilder.builder()
        .entityID(SP)
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .extensions(ExtensionsBuilder.builder()
                .extension(UIInfoBuilder.builder()
                    .displayNames(
                        List.of(new LocalizedString("Display name", "en"), new LocalizedString("Visningsnamn", "sv")))
                    .descriptions(List.of(
                        new LocalizedString("Description", "en"), new LocalizedString("Beskrivning", "sv")))
                    .logos(List.of(
                        LogoBuilder.builder()
                            .height(50)
                            .width(50)
                            .url(SP + "/logo.png")
                            .language("en")
                            .build(),
                        LogoBuilder.builder()
                            .height(150)
                            .width(150)
                            .url(SP + "/logo2.png")
                            .build(),
                        LogoBuilder.builder().build()))
                    .build())
                .build())
            .build())
        .organization(OrganizationBuilder.builder()
            .organizationDisplayNames(
                List.of(new LocalizedString("Organization display name", "en"), new LocalizedString("Organisationsvisningsnamn", "sv"),
                    new LocalizedString("Organisation Anzeigename", "de")))
            .organizationNames(List.of(new LocalizedString("Organization name", "en"), new LocalizedString("Organisationsnamn", "sv"),
                new LocalizedString("Organisationname", "de"), new LocalizedString("Nom de l'organisation", "fr")))
            .build())
        .build();

    final Saml2ServiceProviderUiInfo ui = new Saml2ServiceProviderUiInfo(ed);

    Assertions.assertEquals(SP, ui.getEntityId());
    Assertions.assertTrue(ui.getDisplayNames().size() == 4);
    Assertions.assertEquals("Visningsnamn", ui.getDisplayName("sv"));
    Assertions.assertEquals("Display name", ui.getDisplayName("en"));
    Assertions.assertEquals("Organisation Anzeigename", ui.getDisplayName("de"));
    Assertions.assertEquals("Nom de l'organisation", ui.getDisplayName("fr"));
    Assertions.assertNull(ui.getDisplayName("no"));

    Assertions.assertTrue(ui.getDescriptions().size() == 2);
    Assertions.assertEquals("Beskrivning", ui.getDescription("sv"));
    Assertions.assertEquals("Description", ui.getDescription("en"));
    Assertions.assertNull(ui.getDescription("de"));

    Assertions.assertTrue(ui.getLogotypes().size() == 2);
    Assertions.assertEquals(SP + "/logo2.png", ui.getLogotype((p) -> p.getHeight() > 100).getUrl());
    Assertions.assertEquals("en", ui.getLogotype((p) -> p.getWidth() < 100).getLanguage());
  }

}
