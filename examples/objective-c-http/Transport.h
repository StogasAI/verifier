#import <Foundation/Foundation.h>
#include "stogas_verifier.h"

@interface StogasTransportOwner : NSObject {
    StogasTransport *_handle;
    NSString *_baseURL;
}
@property(readonly, copy) NSString *baseURL;
- (instancetype)initWithConfiguration:(NSDictionary *)configuration;
- (void)close;
@end
