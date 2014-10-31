//
//  RSAutil.h
//  ChatRouter
//
//  Created by Patrik Štrba on 29.3.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#ifndef __ChatRouter__RSAutil__
#define __ChatRouter__RSAutil__

#include <iostream>
#include <cstdio>
#include <cstring>

#include "config.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>

class RSAutil {
public:
    bool loadKey(const unsigned char *data, long length);
    RSA *key;
    
    unsigned char *encode(unsigned char *data, unsigned int length, int *size);
    unsigned char *decode(unsigned char *data, unsigned int length);
    
    static unsigned char *sha256(unsigned char *data, unsigned int length);
private:
    char *base64(unsigned char *input, int length);
};

#endif /* defined(__ChatRouter__RSAutil__) */
