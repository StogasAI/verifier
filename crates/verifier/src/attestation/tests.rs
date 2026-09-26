use super::*;
use serde::Deserialize;
use sha2::Sha256;

#[derive(Deserialize)]
struct Vector {
    count: u16,
    index: u16,
    proof: String,
    report_data: String,
}

fn vectors() -> Vec<Vector> {
    serde_json::from_str(include_str!(
        "../../../../tests/fixtures/attestation-batch-v1.json"
    ))
    .unwrap()
}

fn binding(index: u16) -> Binding {
    let challenge = Sha256::digest(index.to_be_bytes()).into();
    if index.is_multiple_of(2) {
        Binding::NativeTls {
            environment: Environment::Production,
            boot_evidence_sha256: [17; 32],
            challenge,
            signer_spki_sha256: [34; 32],
        }
    } else {
        Binding::E2eeSession {
            environment: Environment::Production,
            boot_evidence_sha256: [17; 32],
            transcript_sha256: challenge,
        }
    }
}

#[test]
fn independent_vectors_bind_every_proof_byte_and_both_channel_profiles() {
    for vector in vectors() {
        let bytes = hex::decode(&vector.proof).unwrap();
        let report: [u8; 64] = hex::decode(&vector.report_data)
            .unwrap()
            .try_into()
            .unwrap();
        let proof = BatchProof::from_bytes(&bytes).unwrap();
        assert_eq!(proof.leaf_count, vector.count);
        assert_eq!(proof.leaf_index, vector.index);
        proof.verify(&binding(vector.index), &report).unwrap();
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(
                !BatchProof::from_bytes(&changed)
                    .is_ok_and(|proof| proof.verify(&binding(vector.index), &report).is_ok()),
                "accepted byte {index} in {}/{}",
                vector.count,
                vector.index
            );
        }
        assert_eq!(
            proof
                .verify(&binding(vector.index + 1), &report)
                .unwrap_err(),
            Error::Binding
        );
        let mut wrong_report = report;
        wrong_report[0] ^= 1;
        assert_eq!(
            proof
                .verify(&binding(vector.index), &wrong_report)
                .unwrap_err(),
            Error::Binding
        );
    }
}

#[test]
fn parser_rejects_excessive_or_incomplete_data_before_retaining_hashes() {
    for bytes in [
        vec![],
        vec![0, 1, 0],
        vec![0, 0, 0, 0],
        vec![0, 1, 0, 1],
        vec![4, 1, 0, 0],
        vec![0, 2, 0, 0],
        vec![0; 4 + 64 * MAX_PROOF_HASHES + 1],
    ] {
        assert!(BatchProof::from_bytes(&bytes).is_err());
    }
    let mut extra = vec![0; 68];
    extra[1] = 1;
    assert_eq!(BatchProof::from_bytes(&extra).unwrap_err(), Error::Shape);
}

#[test]
fn native_binding_commits_boot_challenge_and_signer() {
    let vector = vectors().remove(0);
    let proof = BatchProof::from_bytes(&hex::decode(&vector.proof).unwrap()).unwrap();
    let report: [u8; 64] = hex::decode(&vector.report_data)
        .unwrap()
        .try_into()
        .unwrap();
    for field in 0..3 {
        let Binding::NativeTls {
            environment,
            mut boot_evidence_sha256,
            mut challenge,
            mut signer_spki_sha256,
        } = binding(0)
        else {
            unreachable!()
        };
        match field {
            0 => boot_evidence_sha256[0] ^= 1,
            1 => challenge[0] ^= 1,
            _ => signer_spki_sha256[0] ^= 1,
        }
        assert_eq!(
            proof
                .verify(
                    &Binding::NativeTls {
                        environment,
                        boot_evidence_sha256,
                        challenge,
                        signer_spki_sha256
                    },
                    &report
                )
                .unwrap_err(),
            Error::Binding
        );
    }
}

#[cfg(feature = "staging")]
#[test]
fn production_proofs_cannot_authorize_staging() {
    for vector in vectors().into_iter().take(3) {
        let proof = BatchProof::from_bytes(&hex::decode(&vector.proof).unwrap()).unwrap();
        let report: [u8; 64] = hex::decode(&vector.report_data)
            .unwrap()
            .try_into()
            .unwrap();
        let mut changed = binding(vector.index);
        match &mut changed {
            Binding::NativeTls { environment, .. } | Binding::E2eeSession { environment, .. } => {
                *environment = Environment::Staging;
            }
        }
        assert_eq!(proof.verify(&changed, &report).unwrap_err(), Error::Binding);
    }
}
