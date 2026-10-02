use anyhow::{Context, Result, bail};
use aws_lc_rs::{aead, hkdf};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use std::{
    fs::OpenOptions,
    io::{Read as _, Write as _},
    path::Path,
};
use zeroize::Zeroizing;

fn read_private(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::open(path)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        bail!("Input exceeds its size limit");
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("Cannot create output; existing files are never overwritten")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn key_id(root: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"stogas.customer-key.v1\0");
    hash.update(root);
    hex::encode(hash.finalize())
}

pub fn generate(output: &Path) -> Result<()> {
    let mut root = Zeroizing::new([0_u8; 32]);
    getrandom::fill(root.as_mut()).context("Cannot generate encryption key")?;
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(root.as_ref()));
    write_new(output, encoded.as_bytes())?;
    println!("{}", key_id(root.as_ref()));
    Ok(())
}

fn seal(
    root: &[u8],
    organization: &str,
    purpose: &str,
    plaintext: &[u8],
    salt: &[u8; 32],
    nonce: [u8; 12],
) -> Result<serde_json::Value> {
    let maximum = match purpose {
        "plugins" => 262_144,
        "byok/openai" | "byok/anthropic" | "byok/chutes" => 4096,
        _ => bail!("Unsupported encryption purpose"),
    };
    if root.len() != 32
        || organization.is_empty()
        || organization.contains('\0')
        || plaintext.is_empty()
        || plaintext.len() > maximum
    {
        bail!("Invalid encryption input or size");
    }
    if purpose == "plugins" {
        let value: serde_json::Value = serde_json::from_slice(plaintext)
            .map_err(|_| anyhow::anyhow!("Plugins must contain JSON"))?;
        if !value.is_object() {
            bail!("Plugins must contain a JSON object");
        }
    } else if plaintext.iter().any(|b| !(0x21..=0x7e).contains(b)) {
        bail!("Provider credentials must contain printable ASCII without whitespace");
    }
    let id = key_id(root);
    let context = ["stogas.customer-content.v1", organization, purpose, &id].join("\0");
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(root);
    let info = [context.as_bytes()];
    let okm = prk
        .expand(&info, hkdf::HKDF_SHA256)
        .map_err(|_| anyhow::anyhow!("Cannot derive encryption key"))?;
    let mut material = Zeroizing::new([0_u8; 32]);
    okm.fill(material.as_mut())
        .map_err(|_| anyhow::anyhow!("Cannot derive encryption key"))?;
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, material.as_ref())
            .map_err(|_| anyhow::anyhow!("Cannot initialize encryption"))?,
    );
    let mut encrypted = Zeroizing::new(plaintext.to_vec());
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(context.as_bytes()),
        &mut *encrypted,
    )
    .map_err(|_| anyhow::anyhow!("Cannot encrypt content"))?;
    Ok(
        serde_json::json!({"version":1,"keyId":id,"salt":URL_SAFE_NO_PAD.encode(salt),"nonce":URL_SAFE_NO_PAD.encode(nonce),"blob":URL_SAFE_NO_PAD.encode(encrypted.as_slice())}),
    )
}

pub fn encrypt(
    key_file: &Path,
    organization: &str,
    purpose: &str,
    input: &Path,
    output: &Path,
) -> Result<()> {
    let encoded = read_private(key_file, 128)?;
    let text = std::str::from_utf8(&encoded)
        .context("Invalid key file")?
        .trim();
    let root = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(text)
            .context("Invalid key encoding")?,
    );
    if root.len() != 32 || URL_SAFE_NO_PAD.encode(root.as_slice()) != text {
        bail!("Use a generated 32-byte organization key");
    }
    let maximum = if purpose == "plugins" { 262_144 } else { 4096 };
    let plaintext = read_private(input, maximum)?;
    let mut salt = [0_u8; 32];
    let mut nonce = [0_u8; 12];
    getrandom::fill(&mut salt)?;
    getrandom::fill(&mut nonce)?;
    let envelope = seal(&root, organization, purpose, &plaintext, &salt, nonce)?;
    write_new(output, &serde_json::to_vec_pretty(&envelope)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_independent_webcrypto_vector_and_binds_context() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("customer_encryption_vector.json")).unwrap();
        let root = URL_SAFE_NO_PAD
            .decode(vector["root"].as_str().unwrap())
            .unwrap();
        let expected = &vector["envelope"];
        let salt: [u8; 32] = URL_SAFE_NO_PAD
            .decode(expected["salt"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = URL_SAFE_NO_PAD
            .decode(expected["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let plaintext = vector["plaintext"].as_str().unwrap().as_bytes();
        let organization = vector["organizationId"].as_str().unwrap();
        assert_eq!(
            &seal(&root, organization, "plugins", plaintext, &salt, nonce).unwrap(),
            expected
        );
        assert_ne!(
            seal(&root, "other-org", "plugins", plaintext, &salt, nonce).unwrap()["blob"],
            expected["blob"]
        );
        for (purpose, body) in [
            ("unknown", b"secret".as_slice()),
            ("plugins", b"[]"),
            ("byok/openai", b"secret\n"),
            ("byok/openai", b""),
        ] {
            assert!(seal(&root, organization, purpose, body, &salt, nonce).is_err());
        }
        assert!(
            seal(
                &root,
                organization,
                "byok/openai",
                &vec![b'x'; 4097],
                &salt,
                nonce
            )
            .is_err()
        );
    }

    #[test]
    fn generated_key_is_private_and_never_overwrites() {
        let mut suffix = [0_u8; 16];
        getrandom::fill(&mut suffix).unwrap();
        let path = std::env::temp_dir().join(format!("stogas-key-test-{}", hex::encode(suffix)));
        generate(&path).unwrap();
        let first = std::fs::read(&path).unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&first).unwrap().len(), 32);
        assert!(generate(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), first);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_file(path).unwrap();
    }
}
