#ifndef STOGAS_VERIFIER_H
#define STOGAS_VERIFIER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct StogasVerifier StogasVerifier;

uint32_t stogas_verifier_abi_version(void);

/* Returns NULL unless max_node_age_ms is between 60000 and 180000. */
StogasVerifier *stogas_verifier_new(int64_t max_node_age_ms);

/* The caller must not free a session while another thread is using it. */
void stogas_verifier_free(StogasVerifier *verifier);

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
void stogas_verifier_string_free(char *value);

#ifdef __cplusplus
}
#endif

#endif
