![Logo](images/sweden-connect.png)

# Release Notes

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.spring.saml.idp/spring-saml-idp/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.spring.saml.idp/spring-saml-idp)

### Version 2.3.3

Date: 2025-01-28

- The dependency opensaml-security-ext contained a bug concerning RSA-OAEP och PKCS#11. This has been fixed.

- The custom IdP error messages are now available in Swedish as well as English.

### Version 2.3.2

Date: 2025-01-10

- If the `org.redisson:redisson-spring-boot-starter` is used by the application, but the application has not configured the application for Redis, the application would not start. This has been fixed.

### Version 2.3.1

Date: 2024-12-13

- A new audit logger repository was introduced. It is now possible to configure audit logging to be sent to the underlying logsystem. Using this feature, an appender for, for example, Syslog can be used.

- When using more than one audit logger, multiple log entries were produced from the same base class. This has been fixed.

### Version 2.3.0

Date: 2024-12-08

- The latest version of the [credentials-support](https://docs.swedenconnect.se/credentials-support/) is now used by the library. Using this library, the [Credentials Bundles](https://docs.swedenconnect.se/credentials-support/#the-bundles-concept) concept can by used for a better was of configuring credentials.

- New audit entries for credential monitoring are published, if credential monitoring is being used.

### Version 2.2.1

Date: 2024-11-21

- Support for the eIDAS (optional) attributes Nationality, CountryOfResidence, CountryOfBirth and TownOfBirth was added to attribute conversion logic. This fix only applies to IdP:s that proxy assertions from eIDAS.

- When configuring an HTTPS Metadata Provider it is now possible to configure it with a `https-trust-bundle` to specify which root certificates that are accepted during TLS server certificate validation. See [Metadata Provider Configuration](https://docs.swedenconnect.se/saml-identity-provider/configuration.html#metadata-provider-configuration).

### Version 2.2.0

Date: 2024-10-04

-

The [Saml2ServiceProviderFilter](https://github.com/swedenconnect/saml-identity-provider/blob/main/saml-identity-provider/src/main/java/se/swedenconnect/spring/saml/idp/authnrequest/Saml2ServiceProviderFilter.java) interface was introduced. By declaring a bean of this type, an implementation may add additional restrictions on which Service Provider that are allowed to send requests.

- (embarrassing) We started publishing release notes ...

----

Copyright &copy;
2022-2025, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se).
Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
