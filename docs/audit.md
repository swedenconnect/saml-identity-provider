![Logo](images/sweden-connect.png)

# Identity Provider Auditing

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

-----

The library produces audit log entries using Spring Boot's auditing support, see 
[Spring Boot Authentication Auditing Support](https://www.baeldung.com/spring-boot-authentication-audit).

If you want to be able to obtain audit logs via Spring Boot Actuator you need to:

- Set the property `management.auditevents.enabled` to `true`.

- Include the string `auditevents` among the list specified by the setting 
`management.endpoints.web.exposure.include`.

- Make sure a `org.springframework.boot.actuate.audit.AuditEventRepository` bean exists.

## Audit Events

All audit events will contain the following fields:

- `type` - The type of the audit entry, see below.

- `timestamp` - The timestamp of when the audit event entry was created.

- `principal` - The "owner" of the entry. This will always the the SAML entityID of the Service 
Provider that requested authentication.

- `data` - Auditing data that is specific to the type of audit event. However, the following fields
will always be present:

  - `sp-entity-id` - The "owner" of the entry. This will always the the SAML entityID of the Service Provider that requested authentication. If not available, `unknown` is used.
  
  - `authn-request-id` - The ID of the authentication request that is being processed (`AuthnRequest`). If not available, `unknown` is used.

### Authentication Request Received

**Type:** `SAML2_REQUEST_RECEIVED`

**Description:** An event that is created when a SAML `AuthnRequest` has been received. At this point
the IdP has not performed any checks to validate the correctness of the message.

**Audit data**: `authn-request`

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `id` | The ID of the `AuthnRequest`. | String |
| `issuer` | The entity that issued the authentication request (SP entityID). | String |
| `authn-context-class-refs` | The requested Authentication Context Class References, or, the requested Level of Assurance levels. | A list of strings |
| `force-authn` | Tells whether the SP requires the user to be authenticated. | Boolean |
| `is-passive` | Tells whether the SP requires that no user authentication is performed (i.e., requires SSO). | Boolean |
| `relay-state` | The RelayState variable of the request. | String |

### Before User Authentication

**Type:** `SAML2_BEFORE_USER_AUTHN`

**Description:** The received authentication request has been successfully validated. No additional
data except for the common fields is included. The data is the same as for `SAML2_REQUEST_RECEIVED`
described above.

### After User Authentication

**Type:** `SAML2_AFTER_USER_AUTHN`

**Description:** The Identity Provider has successfully authenticated the user. This can also be
a re-use of a previously performed authentication (SSO). In those cases this is reflected in the
audit data.

**Audit data**: `user-authentication-info`

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `authn-instant` | The instant when the user authenticated. | String |
| `subject-locality` | The subject's locality (IP address). | String |
| `authn-context-class-ref` | The URI for the Authentication Context Class (LoA) under which the authentication was made. | String |
| `authn-authority` | Optional identity of an "authenticating authority", used for proxy IdP:s. | String |
| `user-attributes` | A list of elements listing the user attributes that was issued.<br/>**Note:** This will be a complete list of user attributes as seen be the authenticator. It is not sure that all of them are released in the resulting SAML assertion. This depends on the release policy used. | List of attributes with fields `name` and `value`. |
| `sign-message-displayed` | If the request was sent by a "signature service" SP this field will indicate whether a "sign message" was displayed for the user or not. | Boolean |
| `allowed-to-reuse` | Tells whether the IdP will allow this particular authentication to be re-used in forthcoming operations (i.e., can it be used for SSO?). | Boolean |
| `sso-information` | If the current authentication was re-used from a previous user authentication (SSO) this field contains the fields `original-requester` and `original-authn-request-id`. These fields identify the requesting entity and the ID of the authentication request when the user authenticated. The `authn-instant` (see above) will in these cases be set to this instant. | SsoInfo |


### Successful SAML Response

**Type:** `SAML2_SUCCESS_RESPONSE`

**Description:** An event that is created before a success SAML response is sent. This means that the
request has been processed, the user authenticated and a SAML assertion created.

**Audit data**: `saml-response`

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `id` | The ID of the SAML `Response` message. | String |
| `in-response-to` | The ID of the `AuthnRequest` message that triggered this operation. | String |
| `status.code` | The status code of the operation. Will always be `urn:oasis:names:tc:SAML:2.0:status:Success` | String |
| `issued-at` | The time of issuance. | String |
| `destination` | The "destination" of the response message, i.e., the URL to which the message is posted. | String |
| `is-signed` | Tells whether the message is signed. | Boolean |

**Audit data**: `saml-assertion`

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `id` | The ID of the SAML `Assertion`. | String |
| `in-response-to` | The ID of the `AuthnRequest` message that triggered this operation. | String |
| `is-signed` | Tells whether the assertion is signed. | Boolean |
| `is-encrypted` | Tells whether the assertion is encrypted before being included in the response message. | String |
| `issued-at` | The issuance time for the assertion. | String |
| `issuer` | The entityID of the issuing entity (IdP). | String |
| `authn-instant` | The instant when the user authenticated. | String |
| `subject-id` | The `Subject` identity included in the assertion. | String |
| `subject-locality` | The subject's locality (IP address). | String |
| `authn-context-class-ref` | The URI for the Authentication Context Class (LoA) under which the authentication was made. | String |
| `authn-authority` | Optional identity of an "authenticating authority", used for proxy IdP:s. | String |
| `attributes` | A list of elements listing the SAML attributes that was issued. | List of attributes with fields `name` and `value`. |

### Error SAML Response

**Type:** `SAML2_AUDIT_ERROR_RESPONSE`

**Description:** An event that is created before an error SAML response is sent. The error can represent
a bad request or that the user authentication failed.

Note: The case when the user has cancelled the operation is represented by setting the 
`status.subordinate-code` field to `http://id.elegnamnden.se/status/1.0/cancel`.

**Audit data**: `saml-response`

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `id` | The ID of the SAML `Response` message. | String |
| `in-response-to` | The ID of the `AuthnRequest` message that triggered this operation. | String |
| `status.code` | The main status code of the operation (was the error due to an error by the requester or by the responder?). | String |
| `status.subordinate-code` | The subordinate status code. | String |
| `status.message` | Textual error message. | String
| `issued-at` | The time of issuance. | String |
| `destination` | The "destination" of the response message, i.e., the URL to which the message is posted. | String |
| `is-signed` | Tells whether the message is signed. | Boolean |

### Unrecoverable Error

**Type:** `SAML2_UNRECOVERABLE_ERROR`

**Description:** If an error occurs during processing of an request and the IdP has no means of posting
a SAML error response back, this error is displayed in the user interface. In these cases this is also audited.

**Audit data**: `unrecoverable-error`

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `error-code` | The error code. | String |
| `error-message` | The error message. | String |


---

Copyright &copy; 2022-2023, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
