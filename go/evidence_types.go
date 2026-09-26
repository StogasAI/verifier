package verifier

// VerificationError preserves the core's fixed reason without parsing human-readable messages.
type VerificationError struct {
	Code    string
	Message string
}

func (err *VerificationError) Error() string { return err.Message }

// TrustRoot is a local offline trust seed. Never construct it from downloaded evidence.
type TrustRoot struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// EvidenceOptions selects the environment. A nil Root selects the compiled Stogas authority.
type EvidenceOptions struct {
	Environment string     `json:"environment"`
	Root        *TrustRoot `json:"root,omitempty"`
}

// BootIdentity contains fields returned only after hardware and binding verification.
type BootIdentity struct {
	NodeID               string `json:"node_id"`
	ChipID               string `json:"chip_id"`
	ReportedTCB          string `json:"reported_tcb"`
	BootSHA256           string `json:"boot_sha256"`
	GatewayReleaseID     string `json:"gateway_release_id"`
	SigningPublicKey     string `json:"signing_public_key"`
	HPKEPublicKey        string `json:"hpke_public_key"`
	TLSSPKISHA256        string `json:"tls_spki_sha256"`
	ValidFromUnixMS      int64  `json:"valid_from_unix_ms"`
	ValidUntilUnixMS     int64  `json:"valid_until_unix_ms"`
	IntegratedTimeUnixMS *int64 `json:"integrated_time_unix_ms"`
}

// VerifiedReceipt confirms exact content under a hardware-bound boot key.
type VerifiedReceipt struct {
	NodeID         string `json:"node_id"`
	BootSHA256     string `json:"boot_sha256"`
	RequestSHA256  string `json:"request_sha256"`
	ResponseSHA256 string `json:"response_sha256"`
}
