#include "stogas_verifier.h"
#include <curl/curl.h>
#include <json-c/json.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t cancelled;
static void cancel_request(int signal_number) { (void)signal_number; cancelled = 1; }
static int progress(void *context, curl_off_t download, curl_off_t downloaded,
                    curl_off_t upload, curl_off_t uploaded) {
    (void)context; (void)download; (void)downloaded; (void)upload; (void)uploaded;
    return cancelled != 0;
}

int main(int argc, char **argv) {
    const char *key = getenv("STOGAS_API_KEY"), *model = getenv("STOGAS_MODEL");
    if (!key || !*key || !model || !*model || strpbrk(key, "\r\n")) {
        fputs("Set STOGAS_API_KEY and STOGAS_MODEL.\n", stderr);
        return 1;
    }
    int streaming = argc == 2 && strcmp(argv[1], "--stream") == 0;
    if (argc > 2 || (argc == 2 && !streaming)) {
        fputs("Usage: stogas-request [--stream]\n", stderr);
        return 1;
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return 1;
    signal(SIGINT, cancel_request);

    int result = 1;
    StogasTransport *transport = NULL;
    CURL *http = NULL;
    struct curl_slist *headers = NULL;
    struct json_object *started = NULL, *body = NULL, *ok = NULL, *value = NULL, *base = NULL;
    char *url = NULL;
    const char *configuration = "{}";
    char *raw = stogas_transport_start((const uint8_t *)configuration, strlen(configuration), &transport);
    if (raw) started = json_tokener_parse(raw);
    stogas_verifier_string_free(raw);
    if (!transport || !started || !json_object_object_get_ex(started, "ok", &ok) ||
        !json_object_get_boolean(ok) || !json_object_object_get_ex(started, "value", &value) ||
        !json_object_object_get_ex(value, "base_url", &base) ||
        !json_object_is_type(base, json_type_string)) {
        fputs("Unable to establish verified transport; request not sent.\n", stderr);
        goto cleanup;
    }

    const char *base_url = json_object_get_string(base);
    const char *path = "/responses";
    size_t length = strlen(base_url) + strlen(path) + 1;
    url = malloc(length);
    if (!url) goto cleanup;
    snprintf(url, length, "%s%s", base_url, path);
    body = json_object_new_object();
    if (!body) goto cleanup;
    json_object_object_add(body, "model", json_object_new_string(model));
    json_object_object_add(body, "input", json_object_new_string("Say hello in one sentence."));
    json_object_object_add(body, "stream", json_object_new_boolean(streaming));
    headers = curl_slist_append(NULL, "Content-Type: application/json");
    http = curl_easy_init();
    if (!headers || !http) goto cleanup;

    // libcurl sends one request. Do not add a retry loop around perform().
    curl_easy_setopt(http, CURLOPT_URL, url);
    curl_easy_setopt(http, CURLOPT_PROXY, "");
    curl_easy_setopt(http, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(http, CURLOPT_HTTPAUTH, (long)CURLAUTH_BEARER);
    curl_easy_setopt(http, CURLOPT_XOAUTH2_BEARER, key);
    curl_easy_setopt(http, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(http, CURLOPT_POSTFIELDS, json_object_to_json_string_ext(body, JSON_C_TO_STRING_PLAIN));
    curl_easy_setopt(http, CURLOPT_TIMEOUT, 45L * 60L);
    curl_easy_setopt(http, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(http, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(http, CURLOPT_XFERINFOFUNCTION, progress);
    // The default output callback writes buffered JSON or incremental SSE to stdout.
    CURLcode outcome = curl_easy_perform(http);
    long status = 0;
    curl_easy_getinfo(http, CURLINFO_RESPONSE_CODE, &status);
    if (outcome == CURLE_OK && status >= 200 && status < 300 && !cancelled) {
        result = 0;
    } else {
        fprintf(stderr, "Request incomplete or rejected (HTTP %ld, curl %d). Do not replay automatically.\n",
                status, (int)outcome);
    }

cleanup:
    curl_easy_cleanup(http);
    curl_slist_free_all(headers);
    if (body) json_object_put(body);
    if (started) json_object_put(started);
    free(url);
    stogas_transport_free(transport);
    curl_global_cleanup();
    return result;
}
