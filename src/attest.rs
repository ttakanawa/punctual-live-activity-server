//! Apple App Attest validation. No trust anchors can be supplied by a request.
use crate::protocol::*;
use ciborium::value::Value as Cbor;
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use x509_parser::{extensions::ParsedExtension, parse_x509_certificate, prelude::*};

const ROOT: &[u8] = include_bytes!("../trust/apple-app-attest-root.der");
#[derive(Clone, Debug)]
pub struct Policy {
    pub environment: String,
    pub app_id: String,
    pub allowed_categories: Vec<u32>,
    pub allowed_versions: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Registration {
    pub public_key: Vec<u8>,
    pub receipt: Vec<u8>,
    pub environment: String,
    pub app_id: String,
}
pub fn cbor(bytes: &[u8]) -> ApiResult<Cbor> {
    let mut cursor = Cursor::new(bytes);
    let value = ciborium::de::from_reader(&mut cursor).map_err(|_| ApiError::auth())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(ApiError::auth());
    }
    Ok(value)
}
fn field<'a>(value: &'a Cbor, name: &str) -> ApiResult<&'a Cbor> {
    let Cbor::Map(entries) = value else {
        return Err(ApiError::auth());
    };
    let values: Vec<_> = entries
        .iter()
        .filter(|(k, _)| k.as_text() == Some(name))
        .collect();
    if values.len() != 1 {
        return Err(ApiError::auth());
    }
    Ok(&values[0].1)
}
fn bytes(value: &Cbor) -> ApiResult<&[u8]> {
    value
        .as_bytes()
        .map(Vec::as_slice)
        .ok_or_else(ApiError::auth)
}
fn int(value: &Cbor) -> ApiResult<i128> {
    value
        .as_integer()
        .map(Into::into)
        .ok_or_else(ApiError::auth)
}
fn cose_field(value: &Cbor, key: i128) -> ApiResult<&Cbor> {
    let Cbor::Map(entries) = value else {
        return Err(ApiError::auth());
    };
    let matches: Vec<_> = entries
        .iter()
        .filter(|(k, _)| int(k).ok() == Some(key))
        .collect();
    if matches.len() != 1 {
        return Err(ApiError::auth());
    }
    Ok(&matches[0].1)
}
fn extensions(data: &[u8], policy: &Policy, attestation: bool) -> ApiResult<()> {
    if data.is_empty() {
        return Ok(());
    } // Legacy iOS authenticator data has no extensions.
    let value = cbor(data)?;
    let (category, version) = if attestation {
        ("apple_validation_category_01", "apple_bundle_version_01")
    } else {
        ("validationCategory", "bundleVersion")
    };
    let cat = field(&value, category)?;
    let cat = match cat {
        Cbor::Bytes(b) if b.len() == 4 => {
            u32::from_le_bytes(b[..].try_into().map_err(|_| ApiError::auth())?)
        }
        _ => u32::try_from(int(cat)?).map_err(|_| ApiError::auth())?,
    };
    let version = field(&value, version)?
        .as_text()
        .ok_or_else(ApiError::auth)?;
    if !policy.allowed_categories.contains(&cat)
        || version.is_empty()
        || version.len() > 64
        || !version.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        || (!policy.allowed_versions.is_empty()
            && !policy.allowed_versions.iter().any(|v| v == version))
    {
        return Err(ApiError::auth());
    }
    Ok(())
}
fn parse_cert(data: &[u8]) -> ApiResult<X509Certificate<'_>> {
    let (remaining, c) = parse_x509_certificate(data).map_err(|_| ApiError::auth())?;
    if !remaining.is_empty() {
        return Err(ApiError::auth());
    }
    Ok(c)
}
fn cert_signature(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> ApiResult<()> {
    if cert.issuer() != issuer.subject()
        || cert.signature_algorithm != cert.tbs_certificate.signature
        || cert.signature_value.unused_bits != 0
    {
        return Err(ApiError::auth());
    }
    let public = issuer.public_key().subject_public_key.data.as_ref();
    let signature = cert.signature_value.data.as_ref();
    let message = cert.tbs_certificate.as_ref();
    use sha2::{Digest, Sha384};
    let digest = match cert.signature_algorithm.algorithm.to_id_string().as_str() {
        "1.2.840.10045.4.3.2" => hash(message),
        "1.2.840.10045.4.3.3" => Sha384::digest(message).to_vec(),
        _ => return Err(ApiError::auth()),
    };
    match public.len() {
        65 => VerifyingKey::from_sec1_bytes(public)
            .map_err(|_| ApiError::auth())?
            .verify_prehash(
                &digest,
                &Signature::from_der(signature).map_err(|_| ApiError::auth())?,
            )
            .map_err(|_| ApiError::auth()),
        97 => p384::ecdsa::VerifyingKey::from_sec1_bytes(public)
            .map_err(|_| ApiError::auth())?
            .verify_prehash(
                &digest,
                &p384::ecdsa::Signature::from_der(signature).map_err(|_| ApiError::auth())?,
            )
            .map_err(|_| ApiError::auth()),
        _ => Err(ApiError::auth()),
    }
}
fn certificate_constraints(
    cert: &X509Certificate<'_>,
    ca: bool,
    now: i64,
    ca_below: usize,
) -> ApiResult<()> {
    let now = ASN1Time::from_timestamp(now).map_err(|_| ApiError::auth())?;
    if !cert.validity().is_valid_at(now) {
        return Err(ApiError::auth());
    }
    // Parsing extensions uniquely also rejects duplicate constraint OIDs.
    let bc = cert
        .basic_constraints()
        .map_err(|_| ApiError::auth())?
        .ok_or_else(ApiError::auth)?;
    if bc.value.ca != ca
        || (ca
            && bc
                .value
                .path_len_constraint
                .is_some_and(|n| ca_below > n as usize))
    {
        return Err(ApiError::auth());
    }
    let ku = cert
        .key_usage()
        .map_err(|_| ApiError::auth())?
        .ok_or_else(ApiError::auth)?;
    if (ca && !ku.value.key_cert_sign()) || (!ca && !ku.value.digital_signature()) {
        return Err(ApiError::auth());
    }
    let mut oids = std::collections::HashSet::new();
    for ext in cert.extensions() {
        if !oids.insert(ext.oid.to_id_string()) {
            return Err(ApiError::auth());
        }
        if ext.critical
            && !matches!(
                ext.parsed_extension(),
                ParsedExtension::BasicConstraints(_) | ParsedExtension::KeyUsage(_)
            )
        {
            // Fail closed for unknown critical policy/constraint extensions.
            return Err(ApiError::auth());
        }
        if matches!(ext.parsed_extension(), ParsedExtension::ParseError { .. }) {
            return Err(ApiError::auth());
        }
    }
    Ok(())
}
pub fn verify_chain(chain: &[Vec<u8>], now: i64) -> ApiResult<Vec<u8>> {
    chain_with_root(chain, now, ROOT)
}
fn chain_with_root(chain: &[Vec<u8>], now: i64, root_der: &[u8]) -> ApiResult<Vec<u8>> {
    if !(2..=4).contains(&chain.len()) {
        return Err(ApiError::auth());
    }
    let root = parse_cert(root_der)?;
    certificate_constraints(&root, true, now, chain.len() - 1)?;
    let certs = chain
        .iter()
        .map(|der| parse_cert(der))
        .collect::<ApiResult<Vec<_>>>()?;
    for (i, cert) in certs.iter().enumerate() {
        certificate_constraints(cert, i != 0, now, i.saturating_sub(1))?;
        cert_signature(cert, certs.get(i + 1).unwrap_or(&root))?;
    }
    let public = certs[0].public_key().subject_public_key.data.to_vec();
    let eku = certs[0]
        .extended_key_usage()
        .map_err(|_| ApiError::auth())?
        .ok_or_else(ApiError::auth)?;
    if !eku
        .value
        .other
        .iter()
        .any(|oid| oid.to_id_string() == "1.2.840.113635.100.4.24")
    {
        return Err(ApiError::auth());
    }
    VerifyingKey::from_sec1_bytes(&public).map_err(|_| ApiError::auth())?;
    if public.len() != 65 || public[0] != 4 {
        return Err(ApiError::auth());
    }
    Ok(public)
}
pub fn verify_attestation(
    object: &[u8],
    key: &[u8],
    challenge: &[u8],
    policy: &Policy,
    now: i64,
) -> ApiResult<Registration> {
    attestation_with_root(object, key, challenge, policy, now, ROOT)
}
fn attestation_with_root(
    object: &[u8],
    key: &[u8],
    challenge: &[u8],
    policy: &Policy,
    now: i64,
    root_der: &[u8],
) -> ApiResult<Registration> {
    let value = cbor(object)?;
    if field(&value, "fmt")?.as_text() != Some("apple-appattest") {
        return Err(ApiError::auth());
    }
    let stmt = field(&value, "attStmt")?;
    let chain = field(stmt, "x5c")?
        .as_array()
        .ok_or_else(ApiError::auth)?
        .iter()
        .map(|c| bytes(c).map(Vec::from))
        .collect::<ApiResult<Vec<_>>>()?;
    let public = chain_with_root(&chain, now, root_der)?;
    if hash(&public) != key {
        return Err(ApiError::auth());
    }
    let auth = bytes(field(&value, "authData")?)?;
    if auth.len() < 87 || auth[..32] != hash(policy.app_id.as_bytes()) || auth[33..37] != [0; 4] {
        return Err(ApiError::auth());
    }
    let aaguid: &[u8] = match policy.environment.as_str() {
        "development" => b"appattestdevelop",
        "production" => b"appattest\0\0\0\0\0\0\0",
        _ => return Err(ApiError::auth()),
    };
    if &auth[37..53] != aaguid || auth[53..55] != [0, 32] || &auth[55..87] != key {
        return Err(ApiError::auth());
    }
    let mut cursor = Cursor::new(&auth[87..]);
    let cose: Cbor = ciborium::de::from_reader(&mut cursor).map_err(|_| ApiError::auth())?;
    if int(cose_field(&cose, 1)?)? != 2
        || int(cose_field(&cose, 3)?)? != -7
        || int(cose_field(&cose, -1)?)? != 1
        || bytes(cose_field(&cose, -2)?)? != &public[1..33]
        || bytes(cose_field(&cose, -3)?)? != &public[33..65]
    {
        return Err(ApiError::auth());
    }
    extensions(&auth[87 + cursor.position() as usize..], policy, true)?;
    let leaf = parse_cert(&chain[0])?;
    let nonce_ext = leaf
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == "1.2.840.113635.100.8.2")
        .ok_or_else(ApiError::auth)?;
    let mut composite = auth.to_vec();
    composite.extend(hash(challenge));
    let nonce = hash(&composite);
    let mut expected = vec![0x30, 0x24, 0xa1, 0x22, 0x04, 0x20];
    expected.extend(nonce);
    if nonce_ext.value != expected {
        return Err(ApiError::auth());
    }
    let receipt = bytes(field(stmt, "receipt")?)?.to_vec();
    if receipt.is_empty() || receipt.len() > 65536 {
        return Err(ApiError::auth());
    }
    Ok(Registration {
        public_key: public,
        receipt,
        environment: policy.environment.clone(),
        app_id: policy.app_id.clone(),
    })
}
pub fn verify_assertion(
    object: &[u8],
    public: &[u8],
    client_hash: &[u8],
    policy: &Policy,
    previous: u32,
) -> ApiResult<u32> {
    let value = cbor(object)?;
    let auth = bytes(field(&value, "authenticatorData")?)?;
    let signature = bytes(field(&value, "signature")?)?;
    if auth.len() < 37 || auth[..32] != hash(policy.app_id.as_bytes()) {
        return Err(ApiError::auth());
    }
    let counter = u32::from_be_bytes(auth[33..37].try_into().map_err(|_| ApiError::auth())?);
    if counter <= previous {
        return Err(ApiError::auth());
    }
    extensions(&auth[37..], policy, false)?;
    let mut message = auth.to_vec();
    message.extend(client_hash);
    VerifyingKey::from_sec1_bytes(public)
        .map_err(|_| ApiError::auth())?
        .verify_prehash(
            &hash(&message),
            &Signature::from_der(signature).map_err(|_| ApiError::auth())?,
        )
        .map_err(|_| ApiError::auth())?;
    Ok(counter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose,
    };
    fn encode(value: Cbor) -> Vec<u8> {
        let mut out = vec![];
        ciborium::ser::into_writer(&value, &mut out).unwrap();
        out
    }
    fn params(name: &str, ca: bool) -> CertificateParams {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, name);
        if ca {
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        } else {
            p.is_ca = IsCa::ExplicitNoCa;
            p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(vec![
                1, 2, 840, 113635, 100, 4, 24,
            ])];
        }
        p
    }
    #[test]
    fn complete_attestation_validates_chain_nonce_cose_identity_and_environment() {
        let root_key = KeyPair::generate().unwrap();
        let root_params = params("test root", true);
        let root = root_params.self_signed(&root_key).unwrap();
        let root_issuer = Issuer::new(root_params, &root_key);
        let intermediate_key = KeyPair::generate().unwrap();
        let intermediate_params = params("test intermediate", true);
        let intermediate = intermediate_params
            .signed_by(&intermediate_key, &root_issuer)
            .unwrap();
        let issuer = Issuer::new(intermediate_params, &intermediate_key);
        let leaf_key = KeyPair::generate().unwrap();
        let public = leaf_key.public_key_raw();
        let key = hash(public);
        let policy = Policy {
            environment: "development".into(),
            app_id: format!("TESTPREFIX.{BUNDLE_ID}"),
            allowed_categories: vec![3],
            allowed_versions: vec![],
        };
        let challenge = hash(b"randomized fixture challenge");
        let mut auth = hash(policy.app_id.as_bytes());
        auth.push(0x40);
        auth.extend([0; 4]);
        auth.extend(b"appattestdevelop");
        auth.extend([0, 32]);
        auth.extend(&key);
        let integer = |n: i32| Cbor::Integer(n.into());
        auth.extend(encode(Cbor::Map(vec![
            (integer(1), integer(2)),
            (integer(3), integer(-7)),
            (integer(-1), integer(1)),
            (integer(-2), Cbor::Bytes(public[1..33].to_vec())),
            (integer(-3), Cbor::Bytes(public[33..].to_vec())),
        ])));
        let mut composite = auth.clone();
        composite.extend(hash(&challenge));
        let mut nonce_der = vec![0x30, 0x24, 0xa1, 0x22, 0x04, 0x20];
        nonce_der.extend(hash(&composite));
        let mut leaf_params = params("test leaf", false);
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 2, 840, 113635, 100, 8, 2],
                nonce_der,
            ));
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let object = encode(Cbor::Map(vec![
            (
                Cbor::Text("fmt".into()),
                Cbor::Text("apple-appattest".into()),
            ),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth)),
            (
                Cbor::Text("attStmt".into()),
                Cbor::Map(vec![
                    (
                        Cbor::Text("x5c".into()),
                        Cbor::Array(vec![
                            Cbor::Bytes(leaf.der().to_vec()),
                            Cbor::Bytes(intermediate.der().to_vec()),
                        ]),
                    ),
                    (Cbor::Text("receipt".into()), Cbor::Bytes(vec![1, 2, 3])),
                ]),
            ),
        ]));
        let time = date("2026-11-16T00:00:00Z").unwrap();
        let root_der = root.der();
        assert_eq!(
            attestation_with_root(&object, &key, &challenge, &policy, time, root_der)
                .unwrap()
                .public_key,
            public
        );
        assert!(
            attestation_with_root(&object, &key, b"wrong challenge", &policy, time, root_der)
                .is_err()
        );
        let mut wrong = policy.clone();
        wrong.environment = "production".into();
        assert!(attestation_with_root(&object, &key, &challenge, &wrong, time, root_der).is_err());
        wrong = policy.clone();
        wrong.app_id = "WRONGPREFIX.org.tknw.punctual".into();
        assert!(attestation_with_root(&object, &key, &challenge, &wrong, time, root_der).is_err());
        assert!(
            attestation_with_root(&object, &[0; 32], &challenge, &policy, time, root_der).is_err()
        );
        // The production entry point never trusts this ephemeral test root.
        assert!(verify_attestation(&object, &key, &challenge, &policy, time).is_err());
    }
}
