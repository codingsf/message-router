//
//  structure.h
//  ChatRouter
//
//  Created by Patrik Štrba on 27.3.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#ifndef ChatRouter_structure_h
#define ChatRouter_structure_h

#include "config.h"
#include <iostream>
#include <string>
#include <sstream>
#include <pthread.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <cstring>
#include <ctime>
#include <map>
//#include <multimap.h>
#include <list>
#include <queue>


#include <arpa/inet.h>

class Client;
class Worker;
class Server;
class Node;
class Packet;

struct key {
    key() {
        //memset(data, 0, 32);
    }
    
    bool operator == (key k) const {
        int i;
        for(i=0;i<sizeof(key);i++) {
            if(k.data[i] != data[i])
                return false;
        }
        
        return true;
    }
    bool operator<(const key &k) const {
        int i;
        
        for(i=0;i<sizeof(key);i++) {
            if(data[i] == k.data[i])
                continue;
            else if(data[i] > k.data[i])
                return false;
            else
                return true;
        }
        
        return false;
    }
    
    bool compare(key *k) {
        int i;
        for(i=0;i<sizeof(key);i++) {
            if(k->data[i] != data[i])
                return false;
        }
        
        return true;
    }
    unsigned char data[32]; // SHA 256
};

#define PACKET_MESSAGE 0
#define PACKET_AUTH 1
#define PACKET_AUTH_HASH 2
#define PACKET_AUTH_ACCEPT 6
#define PACKET_ERROR 3
#define PACKET_HANDSHAKE 4
#define PACKET_SEARCH 5

struct packetHeader {
    unsigned short type : 8;
    unsigned long long other: 56; // ONLY FOR PADDING
    unsigned long long length;
    key destination;
    key source;
};

struct packet {
    packetHeader header;
    unsigned char *data;
    
    packet() {
        memset(&this->header, 0, sizeof(packetHeader));
        this->data = NULL;
    }
    
    ~packet() {
        if(this->data != NULL)
            delete this->data;
    }
};

struct dataList {
    char *data;
    unsigned int length;
    
    ~dataList() {
        delete this->data;
    }
};

struct connection {
    struct sockaddr_in *sin;
    struct bufferevent *bev;
};

enum statusConnect {
    DISCONNECT = 0,
    CONNECTING = 1,
    CONNECT = 2
};

struct node {
    // CONNECTION
    connection *conn;
    
    // CONNECTION STATUS
    statusConnect status;
    
    // NUMBER OF FAILED CONNECTIONS
    unsigned short failed;
    
    // MUTEX
    pthread_mutex_t mutex;
    
    // PACKETS
    std::queue<Packet *> packets;
    
    // SUPERNODE FLAG
    bool supernode;
    
    void pushPacket(Packet *p) {
        MLOCK(&this->mutex);
        packets.push(p);
        MUNLOCK(&this->mutex);
    }
    
    // INIT PROPERTIES
    void create(struct bufferevent *bev, struct sockaddr_in *sin) {
        this->conn = new connection;
        this->conn->bev = bev;
        this->conn->sin = sin;
        
        this->status = DISCONNECT;
        this->failed = 0;
        
        // INIT MUTEX
        pthread_mutex_init(&mutex, NULL);
    }
    
    char *getAddress() {
        char *addr = new char[INET_ADDRSTRLEN];

        inet_ntop(
                  AF_INET,
                  (const void*)conn->sin->sin_addr.s_addr,
                  addr,
                  INET_ADDRSTRLEN);
        
        return addr;
    }
    
    // SIGN NODE AS SUPERNODE
    void setSuperNode() {
        supernode = true;
    }
    
    // CHECK SUPERNODE FLAG
    bool isSuperNode() {
        return supernode;
    }
    
    static void readcb(struct bufferevent *bev, void *ptr);
    static void eventcb(struct bufferevent *bev, short events, void *ptr);
    
    bool connect(event_base * base);
    
    bool sendPacket(Packet *p);
};

struct nodeInfo {
    node *n;
    
    Node *sn;
    
    Server *s;
    
    unsigned int buffer_length;
    std::queue<dataList *> buffer;
};

// NODE
#define MAPC std::map<int, Client *>
#define MAPR std::queue<Packet *>
#define MAPK std::multimap<key, Client *>
#define MAPN std::map<key, node *>

#define LISTNODE std::list<node *>

// SUPER-NODE
#define MAPSK std::map<key, Client *>
#define MAPQ std::map<std::string, node *>


void debugPacket(packet *p);
#endif
