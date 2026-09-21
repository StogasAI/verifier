//! SNP node names are a readable encoding of the hardware guest's `REPORT_ID`.

const ADJECTIVES: [&str; 16] = [
    "amber", "bright", "clear", "direct", "early", "firm", "green", "high", "inner", "level",
    "prime", "quiet", "ready", "solid", "steady", "true",
];
const NOUNS: [&str; 16] = [
    "anchor", "beacon", "bridge", "forge", "guard", "harbor", "index", "keystone", "ledger",
    "marker", "nexus", "pivot", "relay", "signal", "vector", "watch",
];

/// Format the sole canonical node ID. Formatting alone does not verify a report or grant trust.
#[must_use]
pub fn snp_node_id(report_id: &[u8; 32]) -> String {
    format!(
        "{}-{}-{}",
        ADJECTIVES[usize::from(report_id[0] >> 4)],
        NOUNS[usize::from(report_id[0] & 15)],
        hex::encode(report_id)
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn shared_vectors_preserve_full_identity_and_word_order() {
        let vectors: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../../../../tests/fixtures/node-ids-v1.json"))
                .unwrap();
        for vector in vectors {
            let report_id = hex::decode(vector["report_id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let actual = super::snp_node_id(&report_id);
            assert_eq!(actual, vector["node_id"]);
            assert!(actual.len() <= 80);
        }
    }
}
