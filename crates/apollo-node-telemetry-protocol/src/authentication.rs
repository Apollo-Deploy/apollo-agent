use crate::ProtocolError;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub fn sign(domain: &[u8], bytes: &[u8], key: &SigningKey) -> Vec<u8> {
    key.sign(&[domain, bytes].concat()).to_bytes().to_vec()
}

pub fn verify(
    domain: &[u8],
    bytes: &[u8],
    signature: &[u8],
    key: &VerifyingKey,
) -> Result<(), ProtocolError> {
    let signature = Signature::from_slice(signature).map_err(|_| ProtocolError)?;
    key.verify_strict(&[domain, bytes].concat(), &signature)
        .map_err(|_| ProtocolError)
}
