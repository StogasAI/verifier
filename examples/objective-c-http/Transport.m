#import "Transport.h"

@implementation StogasTransportOwner
@synthesize baseURL = _baseURL;

- (instancetype)initWithConfiguration:(NSDictionary *)configuration {
    self = [super init];
    if (!self) return nil;
    NSData *bytes = [NSJSONSerialization dataWithJSONObject:configuration options:0 error:NULL];
    if (bytes && stogas_verifier_abi_version() == 1) {
        char *raw = stogas_transport_start(bytes.bytes, bytes.length, &_handle);
        NSData *result = raw ? [NSData dataWithBytes:raw length:strlen(raw)] : nil;
        stogas_verifier_string_free(raw);
        id envelope = result ? [NSJSONSerialization JSONObjectWithData:result options:0 error:NULL] : nil;
        if ([envelope isKindOfClass:[NSDictionary class]] &&
            [[envelope objectForKey:@"ok"] isEqual:@(YES)]) {
            id value = [envelope objectForKey:@"value"];
            id url = [value isKindOfClass:[NSDictionary class]] ? [value objectForKey:@"base_url"] : nil;
            if (_handle && [url isKindOfClass:[NSString class]]) _baseURL = [url copy];
        }
    }
    if (!_baseURL) {
        [self close];
#if !__has_feature(objc_arc)
        [self release];
#endif
        return nil;
    }
    return self;
}

- (void)close {
    stogas_transport_close(_handle);
    stogas_transport_free(_handle);
    _handle = NULL;
}

- (void)dealloc {
    [self close];
#if !__has_feature(objc_arc)
    [_baseURL release];
    [super dealloc];
#endif
}
@end
