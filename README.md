bc-fips Java 17 EdDSA scenario
==============================

This code, in unit test `EdDSAKeySpecTest.java` test method `failWithBCFIPSOnly()`,
demonstrates how

- on Java 17 (and presumably on Java 15+),
- if BCFIPS is used as a security provider, without SunEC,
- then the `EdDSA` KeyFactory from BCFIPS
- cannot generate a public key,
- because `keySpec for PublicKey not recognized: java.security.spec.EdECPublicKeySpec`.
