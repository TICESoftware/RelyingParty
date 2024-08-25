# Relying Party Backend (for EUDI wallet)

This is a work-in-progress prototype providing a relying party backend as counterpart for an EUDI wallet app.

This repository is a fork from the EU Digital Identity Wallet project. The main changes are:
* Add functionality for an [Zero-Knowledge Proof](https://github.com/TICESoftware/ZKP), providing the necessary information.
* Add verification of the tokens received from the wallet app.

# Overview

## Context

This project has been developed as part of the [SPRIND EUDI Wallet Prototypes Challenge](https://www.sprind.org/de/challenges/eudi-wallet-prototypes). The approach is based on variant C of the [German Architecture Proposal](https://gitlab.opencode.de/bmi/eudi-wallet/eidas-2.0-architekturkonzept) (Version 2). In addition a Zero-Knowledge-Proof (ZKP)mechanism has been implemented in order for the wallet to disclose the credentials in a way that enables pausible deniability against third parties.

## Features

This backend is able to handle requests by frontend and apps to showcase the whole presentation flow - with and without Zero-Knowledge Proof.

See more details in the [README from the forked repository](Upstream-README.md].

## Dependencies

The components of the [EU Reference Implementation](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md) have been used as a foundation as much as possible. In order to apply adjustments and feature additions (see above), the repo has been forked. We would love to contribute the changes that have some value to the community once the challenge is concluded.

The ZKP operations are integrated via [ZKP](https://github.com/TICESoftware/ZKP).

## Frontend

Since this application is just for demonstration purposes, the presentation definition and parsing of the received data is done by the [frontend](https://github.com/TICESoftware/wallet-verifier-ui). This is done to be able to demonstrate different scenarios, but should not be used in production.

## Apps

This backend can be used by wallet apps using the OpenId4VP protocol. The ZKP is not yet part of that, but is implemented in those wallet apps:

- [EUDI Wallet for Android](https://github.com/TICESoftware/WalletAndroid)
- [EUDI Wallet for iOS](https://github.com/TICESoftware/wallet-ios)

# Setup and requirements

To run the application, the public key for the issuer is needed (without header and footer (i.e. `BEGIN` and `END` lines) and injected as environment variable `ISSUER_CERT`.

Having that, just clone the repository and build and run the application using Gradle:

```shell
ISSUER_CERT=[...] ./gradlew bootRun
```

# Disclaimer

The software in this repository is still under development and not intended to be used in production.

# License

Copyright 2024 TICE GmbH

This project is licensed under the [Apache v2.0 License](LICENSE).
