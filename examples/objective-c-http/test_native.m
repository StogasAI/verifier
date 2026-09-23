#import "Transport.h"
#include <arpa/inet.h>
#include <unistd.h>

static BOOL connectPort(int port) {
    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0) abort();
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int result = connect(socketFD, (struct sockaddr *)&address, sizeof(address));
    close(socketFD);
    return result == 0;
}

int main(void) {
    @autoreleasepool {
        for (NSString *security in @[@"tls", @"e2ee"]) {
            StogasTransportOwner *transport = [[StogasTransportOwner alloc]
                initWithConfiguration:@{@"environment":@"staging", @"security":security}];
            if (!transport) return 1;
            int port = [[[NSURL URLWithString:transport.baseURL] port] intValue];
            if (!connectPort(port)) return 1;
            @try {
                if ([security isEqual:@"e2ee"]) @throw [NSException exceptionWithName:@"Interrupted" reason:nil userInfo:nil];
            } @catch (NSException *error) { (void)error; }
            @finally { [transport close]; [transport close]; }
            if (connectPort(port)) return 1;
#if !__has_feature(objc_arc)
            [transport release];
#endif
        }
        StogasTransportOwner *invalid = [[StogasTransportOwner alloc]
            initWithConfiguration:@{@"security":@"unknown"}];
        if (invalid) return 1;
        puts("Native ownership and exception cleanup passed");
        return 0;
    }
}
