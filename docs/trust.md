# App Attest trust material

[The PEM root](../trust/Apple_App_Attestation_Root_CA.pem#L1) was downloaded from
[Apple's private PKI page](https://www.apple.com/certificateauthority/private/),
which links directly to
[Apple App Attestation Root CA](https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem).
The DER copy is the identical certificate used by the verifier. Its SHA-256 is
1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932.
These are public certificates, not secrets.

The two DER certificates under the test fixture directory are the expected leaf
and intermediate published in
[Apple's Attestation Object Validation Guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide).
Their historical validity is tested at 2026-04-21T00:00:00Z. They are not trusted
as roots. The guide's complete example has inconsistent key-ID/public-key hash
values, so the service does not weaken that required comparison to accept it.
A separate test builds a valid complete attestation using ephemeral keys and a
test root; the production entry point rejects that root.
