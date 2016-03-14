/*
 * Copyright (c) 2011, Andrew Sorensen
 *
 * All rights reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * Neither the name of the authors nor other contributors may be used to endorse
 * or promote products derived from this software without specific prior written 
 * permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef EXT_THREAD
#define EXT_THREAD

#ifdef _WIN32
#include <thread>
#include <functional>
#else
#include "pthread.h"
#endif


namespace extemp
{

class EXTThread
{
private:
    typedef void* (*function_type)(void*);
private:
    bool          m_initialised;
    bool          m_detached;
    bool          m_joined;
    function_type m_function;
    void*         m_arg;
#ifndef _WIN32
    pthread_t   m_thread;
#else
    std::thread m_thread;
#endif

    static thread_local EXTThread* sm_currentThread;
public:
    EXTThread() : m_initialised(false), m_detached(false), m_joined(false) {
    }
#ifdef _WIN32
    EXTThread(std::thread&& Thread);
#else
    EXTThread(pthread_t Thread);
#endif
    ~EXTThread();

    int create(void *(*EntryPoint)(void*), void* Arg);
    int kill();
    int detach();
    int join();
    bool isRunning() { return m_initialised; }
    bool isCurrentThread() { return sm_currentThread == this; }
    int setPriority(int Priority, bool Realtime);
    int getPriority(); //doesn't say if it's realtime or not
    bool isEqualTo(EXTThread* Other) { return this == Other; }
#ifdef _WIN32
    std::thread& getThread() { return m_thread; }
#else
    pthread_t getThread() { return m_thread; }
#endif

    static void* Trampoline(void* Arg) {
        auto thread(reinterpret_cast<EXTThread*>(Arg));
        sm_currentThread = thread;
        return thread->m_function(thread->m_arg);
    }
    static EXTThread* activeThread() {
        return sm_currentThread;
    }
};

} //End Namespace

#endif
