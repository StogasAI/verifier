#ifndef STOGAS_VERIFIER_H
#define STOGAS_VERIFIER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct StogasVerifier StogasVerifier;
typedef struct StogasTransport StogasTransport;

uint32_t stogas_verifier_abi_version(void);

/* Returns NULL only when allocation fails. */
StogasVerifier *stogas_verifier_new(void);

/* The caller must not free a session while another thread is using it. */
void stogas_verifier_free(StogasVerifier *verifier);

/*
 * Start one managed SDK transport. Configuration is UTF-8 JSON:
 * {
 *   "security": "tls" | "e2ee" | "both",
 *   "bundle_refresh_interval_seconds": 300,
 *   "base_url": "https://api.stogas.ai",
 *   "bundle_url": "https://evidence.stogas.ai/bundles/latest.json"
 * }
 *
 * Optional fields use the secure production defaults. On success, *transport_out owns a live
 * handle and the returned envelope contains {"base_url":"http://127.0.0.1:<port>/<capability>/v1"}.
 */
char *stogas_transport_start(
    const uint8_t *configuration,
    size_t configuration_len,
    StogasTransport **transport_out
);
char *stogas_transport_refresh(const StogasTransport *transport);
void stogas_transport_free(StogasTransport *transport);

/*
 * Each operation returns an owned, NUL-terminated JSON envelope:
 *   {"ok":true,"value":...}
 *   {"ok":false,"error":"..."}
 * Release every non-NULL result with stogas_verifier_string_free.
 */
char *stogas_verifier_verify_bundle(
    const StogasVerifier *verifier,
    const uint8_t *bundle,
    size_t bundle_len,
    int64_t now_unix_ms
);
char *stogas_verifier_verify_response_proof(
    const StogasVerifier *verifier,
    const uint8_t *proof,
    size_t proof_len,
    const uint8_t *request_body,
    size_t request_body_len,
    const uint8_t *response_body,
    size_t response_body_len,
    const uint8_t *e2ee_transcript_sha256,
    size_t e2ee_transcript_sha256_len,
    int64_t now_unix_ms
);
char *stogas_verifier_verify_historical_response_proof(
    const StogasVerifier *verifier,
    const uint8_t *proof,
    size_t proof_len,
    const uint8_t *request_body,
    size_t request_body_len,
    const uint8_t *response_body,
    size_t response_body_len,
    const uint8_t *ledger,
    size_t ledger_len,
    const uint8_t *catalog,
    size_t catalog_len,
    const uint8_t *e2ee_transcript_sha256,
    size_t e2ee_transcript_sha256_len,
    int64_t now_unix_ms
);
void stogas_verifier_string_free(char *value);

#ifdef __cplusplus
}
#endif

#endif
