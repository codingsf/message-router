//
//  config.h
//  ChatRouter
//
//  Created by Patrik Štrba on 28.3.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#ifndef ChatRouter_config_h
#define ChatRouter_config_h

#define _DEBUG_ 1

#if _DEBUG_
    #define log fprintf
#else
    #define log //
#endif

#define NODE_PORT 8002

// LISTENING FOR CLIENTS
#define LISTEN_PORT 8000

#define CLIENT_HASH_SIZE 15 // 255 ^ 10

// LISTENING FOR NODES
#define ROUTER_PORT 8001

// READ BUFFER, MUST BE GREATER THAN PACKET HEADER SIZE !!!!!
#define ROUTER_BUFFER 1024

#define ROUTER_RESPONSE_TIMEOUT 3
#define ROUTER_CONNECT_TIMEOUT 3

#define ROUTER_MAX_FAILED_CONNECTION 5


#define DMLOCK(var) \
    /*log(stderr, "[DEBUG] LOCK %s %d\n", __FILE__, __LINE__);*/ \
    pthread_mutex_lock(var); \
    //log(stderr, "[DEBUG] SUCC LOCK %s %d\n", __FILE__, __LINE__);

#define DMUNLOCK(var) \
    /*log(stderr, "[DEBUG] UNLOCK %s %d\n", __FILE__, __LINE__);*/ \
    pthread_mutex_unlock(var); \
    //log(stderr, "[DEBUG] UNLOCK %s %d\n", __FILE__, __LINE__);


#define MLOCK(var) pthread_mutex_lock(var);
#define MUNLOCK(var) pthread_mutex_unlock(var);

#endif
