//
//  WorkerManager.h
//  ChatRouter
//
//  Created by Patrik Štrba on 12.4.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#ifndef __ChatRouter__WorkerManager__
#define __ChatRouter__WorkerManager__

#include <iostream>
#include <structure.h>
#include <Worker.h>

class WorkerManager {
public:
    void start(unsigned int workers);
};

#endif /* defined(__ChatRouter__WorkerManager__) */
