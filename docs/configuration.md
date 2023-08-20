![Logo](images/sweden-connect.png)

# Identity Provider Configuration and Deployment

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

-----

By including the SAML IdP Spring Boot starter as a dependency you basically get a ready-to-go SAML
IdP.

```
<dependency>
  <groupId>se.swedenconnect.spring.saml.idp</groupId>
  <artifactId>saml-idp-spring-boot-starter</artifactId>
  <version>${saml.idp.version}</version>
</dependency>
```

You will need to supply application properties (described in [Configuration Properties](#configuration-properties) below) and also define at least one [UserAuthenticationProvider](https://github.com/swedenconnect/saml-identity-provider/blob/main/saml-identity-provider/src/main/java/se/swedenconnect/spring/saml/idp/authentication/provider/UserAuthenticationProvider.java) bean. This bean contains the
logic for user authentication. Normally, we need to redirect the user agent (browser) to a separate 
endpoint where user authentication is performed. In those cases the [UserRedirectAuthenticationProvider](https://github.com/swedenconnect/saml-identity-provider/blob/main/saml-identity-provider/src/main/java/se/swedenconnect/spring/saml/idp/authentication/provider/external/UserRedirectAuthenticationProvider.java) is used.

See the supplied example IdP in this project (`demo-boot-idp`), or perhaps even better the [Swedish eID Reference IdP](https://github.com/swedenconnect/swedish-eid-idp).

<a name="configuration-properties"></a>
### Configuration Properties

This section documents all properties that can be provided to configure the IdP.

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `saml.idp.entity-id` | The Identity Provider SAML entityID. | String | Required - No default value |
| `saml.idp.base-url` | The Identity Provider base URL, i.e., the protocol, domain and context path. Must not end with an '/'. | String | Required - No default value |
| `saml.idp.hok-base-url` | The Identity Provider base URL for Holder-of-key support, i.e., the protocol, domain and context path. Must not end '/'. This setting is optional, and if HoK is being used **and** that requires a different IdP domain or context path this setting represents this base URL. | String | - |
| `saml.idp.requires-signed-requests` | Whether the IdP requires signed authentication requests. | Boolean | `true` |
| `saml.idp.clock-skew-adjustment` | Clock skew adjustment (in both directions) to consider for accepting messages based on their age. | Duration | 30 seconds |
| `saml.idp.max-message-age` | Maximum allowed age of received messages. | Duration | 3 minutes |
| `saml.idp.sso-duration-limit` | Based on a previous authentication, for how long may this authentication be re-used? Set to 0 seconds to disable SSO. | Duration | 1 hour |
| `saml.idp.credentials.*` | Configuration for IdP credentials, see [Credentials Configuration](#credentials-configuration) below. | [CredentialConfigurationProperties](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/CredentialConfigurationProperties.java) | No default value, but named beans may be provided (see below). |
| `saml.idp.endpoints.*` | Configuration for the endpoints that the IdP exposes, see [Endpoints Configuration](#endpoints-configuration) below. | [EndpointsConfigurationProperties](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/EndpointsConfigurationProperties.java) | See below. |
| `saml.idp.assertions.*` | Configuration for IdP Assertion issuance, see [Assertion Settings Configuration](#assertion-settings-configuration) below. | [AssertionSettingsConfigurationProperties](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/AssertionSettingsConfigurationProperties.java) | See below. |
| `saml.idp.metadata.*` | Configuration for the SAML metadata produced (and published) by the IdP, see [MetadataConfiguration](#metadata-configuration) below. | [MetadataConfigurationProperties](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/MetadataConfigurationProperties.java) | See below. |
| `saml.idp-metadata-providers[].*` | A list of "metadata providers" that tells how the IdP downloads federation metadata. See [Metadata Provider Configuration](#metadata-provider-configuration) below. | [MetadataProviderConfigurationProperties](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/MetadataProviderConfigurationProperties.java) | See below. |

<a name="credentials-configuration"></a>
#### Credentials Configuration

The IdP needs to be configured with at least one credential (private key and certificate). Each of the credential types below may be created by declared named beans instead of using the property configuration.

See https://github.com/swedenconnect/credentials-support for details about the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) type and how it is configured.

| Property | Description | Type |
| :--- | :--- | :--- |
| `default-credential.*` | The IdP default credential. This will be used if no specific credential is defined for the usages sign, encrypt or metadata signing. <br />It is also possible to define the default credential by declaring a bean of type [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) and name it `saml.idp.credentials.Default`. | [PkiCredentialConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/factory/PkiCredentialConfigurationProperties.java) |
| `sign.*` | The credential the IdP uses to sign (responses and assertions). <br />It is also possible to define the signing credential by declaring a bean of type [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) and name it `saml.idp.credentials.Sign`. | [PkiCredentialConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/factory/PkiCredentialConfigurationProperties.java) |
| `future-sign` | A certificate that will be the future signing certificate. Is set before a key-rollover is performed. <br />It is also possible to define the future signing certificate by declaring a bean of type `X509Certificate` and name it `saml.idp.credentials.FutureSign`. | [Resource](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/core/io/Resource.html) (pointing at a certificate resource). |
| `encrypt.*` | The IdP encryption credential. This will be used by SP:s to encrypt data (the certificate) for the IdP (for example sign messages), and by the IdP to decrypt these messages. If no Sweden Connect features are used, no encrypt-credential is needed.<br />It is also possible to define the encrypt credential by declaring a bean of type [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) and name it `saml.idp.credentials.Encrypt`. | [PkiCredentialConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/factory/PkiCredentialConfigurationProperties.java) |
| `previous-encrypt.*` | The previous IdP encryption credential. Assigned after a key-rollover of the encrypt credential. <br />It is also possible to define the previous encrypt credential by declaring a bean of type [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) and name it `saml.idp.credentials.PreviousEncrypt`. | [PkiCredentialConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/factory/PkiCredentialConfigurationProperties.java) |
| `metadata-sign.*` | The credential the IdP uses to sign its published metadata. <br />It is also possible to define the metadata signing credential by declaring a bean of type [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) and name it `saml.idp.credentials.MetadataSign`.<br /><br />If no metadata sign credential is configured, the default credential will be used. If no default credential exists, metadata published will not be signed. | [PkiCredentialConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/factory/PkiCredentialConfigurationProperties.java) | 

<a name="endpoints-configuration"></a>
#### Endpoints Configuration

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `redirect-authn` | The endpoint where the Identity Provider receives authentication requests via HTTP redirect. | String | `/saml2/redirect/authn` |
| `post-authn` | The endpoint where the Identity Provider receives authentication requests via HTTP POST. | String | `/saml2/post/authn` |
| `hok-redirect-authn` | The endpoint where the Identity Provider receives authentication requests via HTTP redirect where Holder-of-key (HoK) is used. | String | - |
| `hok-post-authn` | The endpoint where the Identity Provider receives authentication requests via HTTP POST where Holder-of-key (HoK) is used. | String | - |
| `metadata` | The SAML metadata publishing endpoint. | String | `/saml2/metadata` |

<a name="assertion-settings-configuration"></a>
#### Assertion Settings Configuration

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `encrypt` | Tells whether the Identity Provider encrypts assertions. | Boolean | `true` |
| `not-after` | A setting that tells the time restrictions the IdP puts on an Assertion concerning "not on or after". | Duration | 5 minutes |
| `not-before` | A setting that tells the time restrictions the IdP puts on an Assertion concerning "not before". | Duration | 10 seconds. |

<a name="metadata-configuration"></a>
#### Metadata Configuration

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `template` | A template for the IdP metadata. This is an XML document containing (partial) SAML metadata. | [Resource](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/core/io/Resource.html) (pointing at a XML-file resource). | - |
| `cache-duration` | Tells how long the published IdP metadata can remain in a cache. | Duration | 24 hours |
| `validity-period` | Tells for how long a published metadata entry should be valid. | Duration | 7 days |
| `ui-info.*` | Configuration for the metadata `UIInfo` element. See the `UIInfo` class in [MetadataConfigurationProperties](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/MetadataConfigurationProperties.java) for details. | [MetadataConfigurationProperties.UIInfo](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/MetadataConfigurationProperties.java) | - |
| `organization.*` | Settings for the `Organization` metadata element. See the `Organization` class in the [MetadataConfigurationProperties](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/MetadataConfigurationProperties.java) for details. | [MetadataConfigurationProperties.Organization](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/MetadataConfigurationProperties.java) | - |
| `contact-persons.*` | A map of the metadata `ContactPerson` elements, where the key is the type and the value is a `ContactPerson`. | [MetadataConfigurationProperties.ContactPerson](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/MetadataConfigurationProperties.java) | - |

<a name="metadata-provider-configuration"></a>
#### Metadata Provider Configuration

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `location` | The location of the metadata. Can be an URL, a file, or even a classpath resource. | [Resource](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/core/io/Resource.html) | - |
| `backup-location` | If the `location` setting is an URL, a "backup location" may be assigned to store downloaded metadata. | [File](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/File.html) | - |
| `mdq` | If the `location` setting is an URL, setting the MDQ-flag means that the metadata MDQ (https://www.ietf.org/id/draft-young-md-query-17.html) protocol is used. | Boolean | `false` |
| `validation-certificate` | The certificate used to validate the metadata. | [Resource](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/core/io/Resource.html) pointing at the certificate resource. | - |
| `http-proxy.*` | If the `location` setting is an URL and a HTTP proxy is required this setting configures this proxy. | [MetadataProviderConfigurationProperties.HttpProxy](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/MetadataProviderConfigurationProperties.java) | - |


---

Copyright &copy; 2022-2023, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
