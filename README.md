![Logo](docs/images/sweden-connect.png)


# Spring Security SAML Identity Provider

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This repository comprises of a Spring Security module for setting up a SAML Identity Provider 
according to the [Swedish eID Framework specifications](https://docs.swedenconnect.se/technical-framework).

-----

## About

The repository comprises of the following modules:

- `saml-identity-provider` - The Spring Security implementation of a SAML Identity Provider.

- `autoconfigure` - A Spring Boot autoconfigure module for the Spring Security SAML IdP.

- `starter` - A Spring Boot starter for the Spring Security SAML IdP.

- `samples` - Examples

    - `demo-boot-idp` - A Spring Boot application using the SAML IdP starter to implement a simple
    SAML IdP.

    - `client` - A SAML SP that can be used to send authentication requests to the example IdP.

## Documentation

- [Java Documentation](https://docs.swedenconnect.se/saml-identity-provider/apidoc/)

- [Configuration and Deployment](docs/configuration.md)

- [Audit Logging](docs/audit.md)

- [Example Application](docs/example.md)


-----

Copyright &copy; 2022-2023, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).