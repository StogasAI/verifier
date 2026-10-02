#ifndef STOGAS_VERIFIER_H
#define STOGAS_VERIFIER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct StogasTransport StogasTransport;
typedef struct StogasEvidence StogasEvidence;
typedef struct StogasEvidenceSnapshot StogasEvidenceSnapshot;
typedef struct StogasChannelSession StogasChannelSession;
typedef struct StogasChannelReader StogasChannelReader;
typedef struct StogasChannelWriter StogasChannelWriter;
typedef struct { uint8_t *data; size_t len; } StogasChannelBuffer;

/* Binary server channel. Root and id are exactly 32 bytes from authenticated
 * setup. ratchet_bytes is even, from 32 through 1152. now_ms is a caller-owned
 * monotonic elapsed clock. Session calls require exclusive access; each accepted
 * reader/writer has an independent owner. Free once after calls finish.
 * Status: 0 success, 1 record, 2 authentication, 3 limit, 4 closed,
 * 5 truncated, 6 pending, 7 crypto, 255 panic (discard the owner).
 * Open/accept decrypt in place and return a borrowed plaintext offset/length.
 * Seal returns owned ciphertext; free it with stogas_channel_buffer_free.
 * Buffers are bounded to 65536 bytes; outputs must not alias inputs or each other.
 */
/* Key outputs are 32 disjoint bytes. Bind the public key into setup and erase the
 * private output after session construction or abandonment. */
uint32_t stogas_channel_key_generate(uint8_t *private_key, uint8_t *public_key);
uint32_t stogas_channel_session_new(const uint8_t *root, const uint8_t *id, const uint8_t *initial_private, uint16_t ratchet_bytes, StogasChannelSession **output);
uint32_t stogas_channel_accept(StogasChannelSession *session, uint64_t number, uint8_t *data, size_t len, uint64_t now_ms, StogasChannelReader **reader, StogasChannelWriter **writer, size_t *offset, size_t *plaintext_len);
uint32_t stogas_channel_session_expire(StogasChannelSession *session, uint64_t now_ms);
uint32_t stogas_channel_open(StogasChannelReader *reader, uint8_t *data, size_t len, uint8_t *kind, size_t *offset, size_t *plaintext_len);
uint32_t stogas_channel_complete(StogasChannelReader *reader);
uint32_t stogas_channel_seal(StogasChannelWriter *writer, uint8_t kind, const uint8_t *data, size_t len, StogasChannelBuffer *output);
void stogas_channel_buffer_free(StogasChannelBuffer buffer);
void stogas_channel_session_free(StogasChannelSession *handle);
void stogas_channel_reader_free(StogasChannelReader *handle);
void stogas_channel_writer_free(StogasChannelWriter *handle);

/* Offline evidence. Configuration: {"environment":"staging"|"prod", "root"?:
 * {"key_id":"...", "public_key":"..."}}. Omit root for the compiled Stogas authority.
 * An explicit root is local caller configuration, never downloaded bundle input.
 * Calls return the same owned JSON envelope, with a fixed `code` on errors.
 * Snapshots own their verified state and may outlive refresh or the verifier.
 * Free handles exactly once, after their concurrent operations finish.
 */
char *stogas_evidence_new(const uint8_t *configuration, size_t configuration_len, StogasEvidence **output);
void stogas_evidence_free(StogasEvidence *handle);
char *stogas_evidence_refresh(const StogasEvidence *handle, const uint8_t *bundle, size_t bundle_len, int64_t now_unix_ms, StogasEvidenceSnapshot **output);
void stogas_evidence_snapshot_free(StogasEvidenceSnapshot *handle);
char *stogas_evidence_verify_registration(const StogasEvidenceSnapshot *handle, const uint8_t *document, size_t document_len, const uint8_t *challenge, size_t challenge_len, int64_t now_unix_ms);
char *stogas_evidence_verify_logged_boot(const StogasEvidenceSnapshot *handle, const uint8_t *document, size_t document_len, const uint8_t *inclusion, size_t inclusion_len, int64_t now_unix_ms);
/* Request/response hashes are exactly 32 binary bytes computed from the signed content.
 * This appraises the logged boot at now_unix_ms; it does not establish inference time.
 * The receipt input is the complete final stogas metadata JSON, including its receipt. */
char *stogas_evidence_verify_receipt(const StogasEvidenceSnapshot *handle, const uint8_t *document, size_t document_len, const uint8_t *inclusion, size_t inclusion_len, const uint8_t *receipt, size_t receipt_len, const uint8_t *request_hash, size_t request_hash_len, const uint8_t *response_hash, size_t response_hash_len, int64_t now_unix_ms);

/* Historical appraisal authenticates the archive at its log-inclusion time.
 * These operations never install current permission or alter learned revocations. */
char *stogas_evidence_verify_archive(const StogasEvidence *handle, const uint8_t *bundle, size_t bundle_len, int64_t now_unix_ms);
char *stogas_evidence_verify_boot_archive(const StogasEvidence *handle, const uint8_t *archive, size_t archive_len, const uint8_t *bundle, size_t bundle_len, int64_t now_unix_ms);
char *stogas_evidence_verify_receipt_archive(const StogasEvidence *handle, const uint8_t *archive, size_t archive_len, const uint8_t *bundle, size_t bundle_len, const uint8_t *receipt, size_t receipt_len, const uint8_t *request_hash, size_t request_hash_len, const uint8_t *response_hash, size_t response_hash_len, int64_t now_unix_ms);

uint32_t stogas_verifier_abi_version(void);

/*
 * Start one managed SDK transport. Configuration is UTF-8 JSON:
 * {
 *   "environment": "prod",
 *   "security": "tls",
 *   "max_connections": 4
 * }
 *
 * These are the defaults. security accepts tls or e2ee; staging requires a staging build.
 * Optional base_url overrides the HTTPS origin, never the compiled evidence authorities.
 * Connections/sessions open lazily. There is no evidence polling or inference replay.
 * On success, *transport_out owns a live
 * handle and the returned envelope contains {"base_url":"http://127.0.0.1:<port>/<capability>/v1"}.
 */
char *stogas_transport_start(
    const uint8_t *configuration,
    size_t configuration_len,
    StogasTransport **transport_out
);
/* Manual refresh returns whether the verified bundle contents changed. */
char *stogas_transport_refresh(const StogasTransport *transport);
/* Explicit graceful close waits up to five seconds for active work; it retains the handle. */
void stogas_transport_close(const StogasTransport *transport);
/* Release exactly once after concurrent calls finish. Finalizers may use this without waiting.
 * Explicit disposal should call close first, then free. */
void stogas_transport_free(StogasTransport *transport);

/*
 * Each operation returns an owned, NUL-terminated JSON envelope:
 *   {"ok":true,"value":...}
 *   {"ok":false,"error":"..."}
 * Release every non-NULL result with stogas_verifier_string_free.
 */
void stogas_verifier_string_free(char *value);

#ifdef __cplusplus
}
#endif

#endif
