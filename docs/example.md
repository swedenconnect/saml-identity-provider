![Logo](images/sweden-connect.png)


# Identity Provider Example Application

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.spring.saml.idp/spring-saml-idp/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.spring.saml.idp/spring-saml-idp)

The [samples directory](https://github.com/swedenconnect/saml-identity-provider/tree/main/samples)
contains a example SAML IdP using the SAML IdP Spring Boot starter and a
test SAML SP that can be used to send SAML authentication requests to the IdP and to receive and
process SAML response messages.

You should be able to use the default configuration for the applications and just build and run them.
The only thing you need to do is to map "127.0.0.1" to `local.dev.swedenconnect.se` in your hosts file.

Open your web browser and go to the test client: `https://localhost:8445/client/`.

-----

Copyright &copy; 2022-2024, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).