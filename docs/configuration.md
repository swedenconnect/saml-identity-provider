![Logo](images/sweden-connect.png)

# Identity Provider Configuration and Deployment

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.spring.saml.idp/spring-saml-idp/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.spring.saml.idp/spring-saml-idp)

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
| `saml.idp.audit.*` | Audit logging configuration. See [Audit Configuration](#audit-configuration) below. | [AuditRepositoryConfigurationProperties](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/audit/AuditRepositoryConfigurationProperties.java) | See below. |
| `saml.idp.replay.*` | Configuration for message replay checking. See [Replay Checker Configuration](#replay-checker-configuration) below. | [ReplayCheckerConfigurationProperties](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/IdentityProviderConfigurationProperties.java) | See below. |
| `saml.idp.session.module` | The session module to use. Supported values are "memory" and "redis". Set to other value if you extend the IdP with your own session handling. | String | If Redis and Spring Session are available `redis` is the default, otherwise `memory`. |

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
| `template` | A template for the SAML metadata. This is an XML document containing (partial) SAML metadata. | [Resource](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/core/io/Resource.html) (pointing at a XML-file resource). | - |
| `cache-duration` | Tells how long the published metadata can remain in a cache. | Duration | 24 hours |
| `validity-period` | Tells for how long a published metadata entry should be valid. | Duration | 7 days |
| `digest-methods[]` | A list of algorithm URI:s representing the `alg:DigestMethod` elements to include in the metadata. | List of strings. | - |
| `include-digest-methods`<br />`-under-role` | Tells whether `alg:DigestMethod` elements should be placed in an `Extensions` element under the role descriptor (i.e., the `IDPSSODescriptor`). If `false`, the `alg:DigestMethod`elements are included as elements in the `Extensions` element of the `EntityDescriptor`. | Boolean | `false` |
| `signing-methods[].*` | The `alg:SigningMethod` elements to include in the metadata. Each element is configured with `algorithm` that identifier the algorithm by means of the URL defined for its use with the XML Signature specification, and optionally `min-key-size` which is the smallest key size, in bits, that the entity supports in conjunction with the algorithm and `max-key-size` which is the largest key size, in bits, that the entity supports in conjunction with the algorithm. | List of [MetadataConfigurationProperties.SigningMethod](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/MetadataConfigurationProperties.java) | - |
| `include-signing-methods`<br />`-under-role` | Tells whether `alg:SigningMethod` elements should be placed in an `Extensions` element under the role descriptor (i.e., the `IDPSSODescriptor`). If `false`, the `alg:SigningMethod`elements are included as elements in the `Extensions` element of the `EntityDescriptor`. | Boolean | `false` |
| `encryption-methods[].*` | The `md:EncryptionMethod` elements that should be included under the `md:KeyDescriptor` for the encryption key. Note that these algorithms must match the configured encryption key. | See [Encryption Methods](#encryption-methods) below. | - |
| `ui-info.*` | Configuration for the metadata `UIInfo` element. See the `UIInfo` class in [MetadataConfigurationProperties](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/MetadataConfigurationProperties.java) for details. | [MetadataConfigurationProperties.UIInfo](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/MetadataConfigurationProperties.java) | - |
| `organization.*` | Settings for the `Organization` metadata element. See the `Organization` class in the [MetadataConfigurationProperties](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/MetadataConfigurationProperties.java) for details. | [MetadataConfigurationProperties.Organization](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/MetadataConfigurationProperties.java) | - |
| `contact-persons.*` | A map of the metadata `ContactPerson` elements, where the key is the type and the value is a `ContactPerson`. | [MetadataConfigurationProperties.ContactPerson](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/MetadataConfigurationProperties.java) | - |

<a name="encryption-methods"></a>
##### Encryption Methods

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `algorithm` | The algorithm URI of the encryption method. | String | - |
| `key-size` | The key size. | Integer | - |
| `oaep-params` | The OAEP parameters (in Base64-encoding). | String | - |
| `digest-method` | If `algorithm` indicates a key transport algorithm where the digest algorithm needs to be given, this field should be set to this algorithm URI. | String | - |

<a name="metadata-provider-configuration"></a>
#### Metadata Provider Configuration

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `location` | The location of the metadata. Can be an URL, a file, or even a classpath resource. | [Resource](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/core/io/Resource.html) | - |
| `backup-location` | If the `location` setting is an URL, a "backup location" may be assigned to store downloaded metadata. | [File](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/File.html) | - |
| `mdq` | If the `location` setting is an URL, setting the MDQ-flag means that the metadata MDQ (https://www.ietf.org/id/draft-young-md-query-17.html) protocol is used. | Boolean | `false` |
| `validation-certificate` | The certificate used to validate the metadata. | [Resource](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/core/io/Resource.html) pointing at the certificate resource. | - |
| `http-proxy.*` | If the `location` setting is an URL and a HTTP proxy is required this setting configures this proxy.<br /><br />**Note:** This setting is only needed if you require another HTTP proxy that what is configured for the system, or if the system HTTP proxy settings are not set. If Java's HTTP proxy settings are set (see [Java Networking and Proxies](https://docs.oracle.com/javase/8/docs/technotes/guides/net/proxies.html)), these settings will be used by the metadata provider. | [MetadataProviderConfigurationProperties.HttpProxy](https://github.com/swedenconnect/saml-identity-provider/blob/main/autoconfigure/src/main/java/se/swedenconnect/spring/saml/idp/autoconfigure/settings/MetadataProviderConfigurationProperties.java) | - |

<a name="audit-configuration"></a>
#### Audit Configuration

The SAML IdP Spring Boot starter offers automatic support for setting up a [AuditEventRepository](https://docs.spring.io/spring-boot/docs/current/api/org/springframework/boot/actuate/audit/AuditEventRepository.html) bean
based on the below settings. Also see the [Identity Provider Auditing](audit.html) page.

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `file.log-file` | For audit logging to a file. | String | - |
| `im-memory.capacity` | For audit logging to an in-memory repository. Sets the capacity (number of stored events) of this repository. | Integer | - |
| `redis.name` | For logging to Redis. The name of the Redis list/time series object that will hold the audit events. | String | - |
| `redis.type` | For logging to Redis. The type of Redis storage - "list" or "timeseries". Note that Redisson is required for Redis Timeseries. | String | - |
| `include-events[]` | A list of event ID:s for the events that will be logged to the repository. If not set, all events will be logged (except to excluded by the `exclude-events`). | List of strings | Empty list |
| `exclude-events[]` | A list of event ID:s to exclude from being logged to the repository. See also the `include-events` setting. | List of strings | Empty list |

If no repository is configured and no [AuditEventRepository](https://docs.spring.io/spring-boot/docs/current/api/org/springframework/boot/actuate/audit/AuditEventRepository.html) bean exists, an in-memory
repository with the `capacity` set to `1000` will be created.

<a name="replay-checker-configuration"></a>
#### Replay Checker Configuration

The SAML IdP makes use of a [MessageReplayChecker](https://docs.swedenconnect.se/opensaml-addons/apidoc/se/swedenconnect/opensaml/saml2/response/replay/MessageReplayChecker.html) to protect against replay
attacks (i.e., that an authentication request is "replayed"). 

If no [MessageReplayChecker](https://docs.swedenconnect.se/opensaml-addons/apidoc/se/swedenconnect/opensaml/saml2/response/replay/MessageReplayChecker.html) bean is provided by the application the
IdP Spring Boot starter will create this bean (using the configuration settings below).

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `type` | The type of replay checker. Supported values are "memory" and "redis". If set to "redis", Redis must be available and configured. | String | If Redis is available, `redis` is the default, otherwise `memory` |
| `expiration` | For how long should authentication request ID:s be stored in the cache before they expire? | [Duration](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/time/Duration.html) | 5 minutes |
| `context` | Under which context should the cache be stored? Applies to repositories that persist/distribute the cache. | String | `idp-replay-checker` |

<a name="redis-configuration"></a>
#### Redis Configuration

Redis may be used for session handling and/or replay checking. 

How Redis is configured and setup for Spring Boot is described here:

- [Spring Boot Reference Documentation - Common Application Properties](https://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#appendix.application-properties)
- [Spring Session Redis](https://docs.spring.io/spring-session/reference/configuration/redis.html)
- [Spring Data Redis](https://spring.io/projects/spring-data-redis/)

The SAML IdP Spring Boot Starter defines a few extensions to the core Spring Redis configuration:

The setting `spring.data.redis.ssl-ext.enable-hostname-verification` may be set to `false` in
order to turn off hostname verification when SSL/TLS is configured (using [SslBundles](https://spring.io/blog/2023/06/07/securing-spring-boot-applications-with-ssl/)) for the Redis connection. This can 
be useful during testing.

Example:

```
spring:
  ...
  data:
    redis:
      ...
      ssl:      
        enabled: true        
        bundle: redis-tls-bundle
      ssl-ext:
        enable-hostname-verification: false
```

It Redisson is used for the Redis client, the starter also adds extended support to configure
Redis clusters:

In order to configure Redis Clusters NAT translation for addresses have been added. This is done
so that the application knows how to reach the Redis cluster if it is not located on the same network.
This can be done under the key `spring.data.redis.cluster-ext`. This property key is a list of
entries as described below:

| Property | Description | Type |
| :--- | :--- | :--- |
| `nat-translation[].from` | Address to translate from. e.g. "172.20.0.31:2001". | String |
| `nat-translation[].to`| Address to translate to, e.g., "redis1.local.dev.swedenconnect.se:2001". | String |
| `read-mode`| Set cluster read mode to either `SLAVE`, `MASTER` or `MASTER_SLAVE`. The default value is `MASTER` since read/write is highly coupled in Spring Session, selecting `SLAVE` can result in race-conditions leading to the session not being synchronized to the slave in time causing errors. | String |

**Example:**

The three Redis nodes are exposed via NAT to the application on redis(1-3).local.dev.swedenconnect.se.
But internally they refer to eachother as 172.20.0.3(1-3).
When the application connects to the first node, it will reconfigure itself by reading the configuration
from redis1.

Since the application is not located on the same network the connection will fail since those addresses are not located on the same network.

This solution is to add the configuration below that will re-map outgoing connections to the correct node.

```yaml
spring:
  ...
  data:
    redis:
      cluster:
        nodes:
          - redis1.local.dev.swedenconnect.se:2001
          - redis2.local.dev.swedenconnect.se:2002
          - redis3.local.dev.swedenconnect.se:2003
      cluster-ext:
        nat-translation:
          - from: "172.20.0.31:2001"
            to: "redis1.local.dev.swedenconnect.se:2001"
          - from: "172.20.0.32:2002"
            to: "redis2.local.dev.swedenconnect.se:2002"
          - from: "172.20.0.33:2003"
            to: "redis3.local.dev.swedenconnect.se:2003"
```


---

Copyright &copy; 2022-2024, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
