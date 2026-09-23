#import "Transport.h"
#include <curl/curl.h>
#include <json-c/json.h>
#include <signal.h>

static volatile sig_atomic_t cancelled;
static void cancelRequest(int value) { (void)value; cancelled = 1; }
static int progress(void *context, curl_off_t a, curl_off_t b, curl_off_t c, curl_off_t d) {
    (void)context; (void)a; (void)b; (void)c; (void)d;
    return cancelled != 0;
}

static BOOL printContent(NSData *data, NSString *field) {
    struct json_tokener *parser = json_tokener_new();
    if (!parser) return NO;
    json_tokener_set_flags(parser, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    struct json_object *value = json_tokener_parse_ex(parser, data.bytes, (int)data.length);
    BOOL valid = json_tokener_get_error(parser) == json_tokener_success && json_object_is_type(value, json_type_object);
    json_tokener_free(parser);
    struct json_object *error = NULL, *choices = NULL;
    if (valid && json_object_object_get_ex(value, "error", &error)) valid = NO;
    if (valid && json_object_object_get_ex(value, "choices", &choices) && json_object_is_type(choices, json_type_array)) {
        for (size_t i = 0; i < json_object_array_length(choices); i++) {
            struct json_object *choice = json_object_array_get_idx(choices, i), *message = NULL, *content = NULL;
            if (json_object_object_get_ex(choice, field.UTF8String, &message) &&
                json_object_object_get_ex(message, "content", &content) && json_object_is_type(content, json_type_string)) {
                fputs(json_object_get_string(content), stdout);
            }
        }
    }
    json_object_put(value);
    fflush(stdout);
    return valid;
}

@interface Response : NSObject {
@public
    NSMutableData *line, *data;
    BOOL streaming, complete, skipLF, hasData;
    NSUInteger eventSize;
    CURL *http;
}
- (BOOL)receive:(const char *)bytes length:(size_t)length;
@end

@implementation Response
- (instancetype)init {
    self = [super init];
    if (self) { line = [NSMutableData new]; data = [NSMutableData new]; }
    return self;
}
- (BOOL)finishLine {
    if (!line.length) {
        if (hasData) {
            if (complete) return NO;
            if (data.length == 6 && memcmp(data.bytes, "[DONE]", 6) == 0) complete = YES;
            else if (!printContent(data, @"delta")) return NO;
        }
        [data setLength:0]; hasData = NO; eventSize = 0;
    } else {
        const char *bytes = line.bytes;
        NSUInteger prefix = line.length >= 5 && memcmp(bytes, "data:", 5) == 0 ? 5 : 0;
        if (prefix || (line.length == 4 && memcmp(bytes, "data", 4) == 0)) {
            if (!prefix) prefix = 4;
            if (prefix < line.length && bytes[prefix] == ' ') prefix++;
            if (hasData) [data appendBytes:"\n" length:1];
            [data appendBytes:bytes + prefix length:line.length - prefix]; hasData = YES;
        }
    }
    [line setLength:0];
    return YES;
}
- (BOOL)receive:(const char *)bytes length:(size_t)length {
    long status = 0;
    curl_easy_getinfo(http, CURLINFO_RESPONSE_CODE, &status);
    if (cancelled || status != 200) return NO;
    if (!streaming) {
        if (length > 32 * 1024 * 1024 - data.length) return NO;
        [data appendBytes:bytes length:length]; return YES;
    }
    for (size_t i = 0; i < length; i++) {
        char byte = bytes[i];
        if (skipLF && byte == '\n') { skipLF = NO; continue; }
        skipLF = byte == '\r';
        if (byte == '\n' || byte == '\r') {
            if (![self finishLine]) return NO;
        } else {
            if (++eventSize > 8 * 1024 * 1024) return NO;
            [line appendBytes:&byte length:1];
        }
    }
    return YES;
}
- (void)dealloc {
#if !__has_feature(objc_arc)
    [line release]; [data release]; [super dealloc];
#endif
}
@end

static size_t receive(char *bytes, size_t size, size_t count, void *context) {
    if (size && count > SIZE_MAX / size) return 0;
    @autoreleasepool {
        @try {
            Response *response = (__bridge Response *)context;
            return [response receive:bytes length:size * count] ? size * count : 0;
        } @catch (NSException *error) { (void)error; return 0; }
    }
}

int main(int argc, char **argv) {
    @autoreleasepool {
        BOOL streaming = argc == 1;
        if (argc > 2 || (argc == 2 && strcmp(argv[1], "--no-stream"))) return 1;
        NSDictionary *environment = [[NSProcessInfo processInfo] environment];
        NSString *key = [environment objectForKey:@"STOGAS_API_KEY"];
        NSString *model = [environment objectForKey:@"STOGAS_MODEL"];
        if (!key.length || !model.length || [key rangeOfCharacterFromSet:[NSCharacterSet newlineCharacterSet]].location != NSNotFound) return 1;
        StogasTransportOwner *transport = nil;
        NSString *base = [environment objectForKey:@"STOGAS_BASE_URL"];
        if (!base) { transport = [[StogasTransportOwner alloc] initWithConfiguration:@{}]; base = transport.baseURL; }
        NSURL *parsed = [NSURL URLWithString:base ?: @""];
        if (![[parsed scheme] isEqual:@"http"] || ![[parsed host] isEqual:@"127.0.0.1"] || [parsed user]) {
            [transport close];
#if !__has_feature(objc_arc)
            [transport release];
#endif
            return 1;
        }
        int result = 1;
        curl_global_init(CURL_GLOBAL_DEFAULT);
        CURL *http = curl_easy_init();
        struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
        Response *response = [Response new]; response->streaming = streaming; response->http = http;
        @try {
            if (!http || !headers) @throw [NSException exceptionWithName:@"Setup" reason:nil userInfo:nil];
            NSData *body = [NSJSONSerialization dataWithJSONObject:@{
                @"model":model, @"stream":@(streaming),
                @"messages":@[@{@"role":@"user", @"content":@"Say hello in one sentence."}]
            } options:0 error:NULL];
            if (!body) @throw [NSException exceptionWithName:@"JSON" reason:nil userInfo:nil];
            signal(SIGINT, cancelRequest);
            curl_easy_setopt(http, CURLOPT_URL, [[base stringByAppendingString:@"/chat/completions"] UTF8String]);
            curl_easy_setopt(http, CURLOPT_PROXY, "");
            curl_easy_setopt(http, CURLOPT_FOLLOWLOCATION, 0L);
            curl_easy_setopt(http, CURLOPT_HTTPAUTH, (long)CURLAUTH_BEARER);
            curl_easy_setopt(http, CURLOPT_XOAUTH2_BEARER, [key UTF8String]);
            curl_easy_setopt(http, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(http, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body.length);
            curl_easy_setopt(http, CURLOPT_COPYPOSTFIELDS, body.bytes);
            curl_easy_setopt(http, CURLOPT_CONNECTTIMEOUT, 15L);
            curl_easy_setopt(http, CURLOPT_TIMEOUT, 45L * 60L);
            curl_easy_setopt(http, CURLOPT_NOSIGNAL, 1L);
            curl_easy_setopt(http, CURLOPT_NOPROGRESS, 0L);
            curl_easy_setopt(http, CURLOPT_XFERINFOFUNCTION, progress);
            curl_easy_setopt(http, CURLOPT_WRITEFUNCTION, receive);
            curl_easy_setopt(http, CURLOPT_WRITEDATA, (__bridge void *)response);
            CURLcode outcome = curl_easy_perform(http);
            long status = 0; curl_easy_getinfo(http, CURLINFO_RESPONSE_CODE, &status);
            if (outcome == CURLE_OK && status == 200 && !cancelled &&
                (streaming ? response->complete && !response->hasData && !response->line.length : printContent(response->data, @"message"))) {
                result = 0; puts("");
            }
        } @catch (NSException *error) { (void)error; }
        @finally {
            curl_easy_cleanup(http); curl_slist_free_all(headers); curl_global_cleanup();
            [transport close];
#if !__has_feature(objc_arc)
            [transport release]; [response release];
#endif
        }
        if (result) fputs("Request failed or incomplete. Do not replay automatically.\n", stderr);
        return result;
    }
}
