//
//  RouterManager.cpp
//  ChatRouter
//
//  Created by Patrik Štrba on 13.4.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#include "RouterManager.h"

void RouterManager::addNode(node *n) {
    nodes.push_back(n);
}