//
//  RSAutil.cpp
//  ChatRouter
//
//  Created by Patrik Štrba on 29.3.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#include "RSAutil.h"

bool RSAutil::loadKey(const unsigned char *data, long length) {
    key = d2i_RSA_PUBKEY(NULL, &data, length);
    if(key == NULL)
        return false;
    
    return true;
}

char *RSAutil::base64(unsigned char *input, int length) {
    BIO *bmem, *b64;
    
    BUF_MEM *bptr;
    
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    
    char *out = new char[bptr->length+1];
    memcpy(out, bptr->data, bptr->length);
    out[bptr->length] = 0;
    
    BIO_free_all(b64);
    
    return out;
    
}

unsigned char *RSAutil::encode(unsigned char *data, unsigned int length, int *size) {
    unsigned char *buffer = new unsigned char[512];
    
    memset(buffer, 0, 512);
    
    *size = RSA_public_encrypt(length, data, buffer, key, RSA_PKCS1_PADDING);
    
    if(*size == -1) {
        log(stderr, "[DEBUG] RSA bas encrypt\n");
        return NULL;
    }
    
    return buffer;
}


unsigned char *RSAutil::decode(unsigned char *data, unsigned int length) {
    unsigned char *buffer = new unsigned char[RSA_size(key)];
    
    
    int bufsize = RSA_public_decrypt(length, data, buffer, key, RSA_PKCS1_PADDING);
    
    if(bufsize == -1) {
        log(stderr, "[DEBUG] RSA bas decrypt\n");
        return NULL;
    }
    
    return buffer;
}

unsigned char *RSAutil::sha256(unsigned char *data, unsigned int length) {
    unsigned char *hash = new unsigned char[SHA256_DIGEST_LENGTH];
    
    
    
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, data, length);
    SHA256_Final(hash, &sha);
    
    return hash;
    
}