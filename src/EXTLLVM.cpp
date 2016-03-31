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

///////////////////
// LLVM includes //
///////////////////

// must be included before anything which pulls in <Windows.h>
#include "llvm/AsmParser/Parser.h"
#include "llvm/Config/llvm-config.h" // for LLVM_VERSION_STRING
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/ExecutionEngine/Interpreter.h"
#include "llvm/ExecutionEngine/MCJIT.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/LinkAllPasses.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/Support/MemoryObject.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCContext.h"

#include <fstream>
#include "stdarg.h"
#include "EXTLLVM.h"
#include "EXTThread.h"
#include "UNIV.h"
#include "SchemeFFI.h"
#include "TaskScheduler.h"
#include "Scheme.h"
#include "pcre.h"
#include "OSC.h"
#include "math.h"
#include "BranchPrediction.h"

#ifdef _WIN32
#include <malloc.h>
#else
#include <sys/types.h>
#endif

#ifdef __linux__
#include <sys/syscall.h>
#endif

#ifdef EXT_BOOST
#include <boost/asio.hpp>
#else
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>         /* host to IP resolution       */
#include <sys/fcntl.h>
#include <arpa/inet.h>
#endif

#ifdef _WIN32
#include <chrono>
#include <thread>
#elif EXT_BOOST
#include <thread>
#endif

#ifndef _WIN32
#include <unistd.h>
#endif

#include "SchemeProcess.h"

#define DEBUG_ZONE_STACK 0
#define DEBUG_ZONE_ALLOC 0
#define LEAKY_ZONES 1
#define EXTENSIBLE_ZONES 1

// llvm_scheme foreign function -> string name
// also is not thread safe!
std::map<foreign_func,std::string> LLVM_SCHEME_FF_MAP;

// this must be global. we should therefore
// make it thread safe but I'm not going to bother
// while still testing.
std::map<std::string,std::string> LLVM_STR_CONST_MAP;

extemp::EXTMutex alloc_mutex("alloc mutex");

//#ifdef _WIN32
//double log2(double num) {
//	return log(num)/log(2.0);
//}
//#endif

// double (&cosd)(double) = cos;
// double (&tand)(double) = tan;
// double (&sind)(double) = sin;
// double (&coshd)(double) = cosh;
// double (&tanhd)(double) = tanh;
// double (&sinhd)(double) = sinh; 
// double (&acosd)(double) = acos;
// double (&asind)(double) = asin; 
// double (&atand)(double) = atan;
// double (&atan2d)(double,double) = atan2;
// double (&ceild)(double) = ceil;
// double (&floord)(double) = floor;
// double (&expd)(double) = exp;
// double (&fmodd)(double,double) = fmod;
// double (&powd)(double,double) = pow;
// double (&logd)(double) = log;
// double (&log2d)(double) = log2;
// double (&log10d)(double) = log10;
// double (&sqrtd)(double) = sqrt;
// double (&fabsd)(double) = fabs;

void* malloc16(size_t s)
{
  unsigned char *p;
  unsigned char *porig = (unsigned char*) malloc (s + 0x10);   // allocate extra
  if (porig == NULL) return NULL;                              // catch out of memory
  p = (unsigned char*) (((uintptr_t) porig + 16) & (~0x0f));   // insert padding
  *(p-1) = p - porig;                                          // store padding size
  return p;
}

void free16(void *p) {
  unsigned char *porig = (unsigned char*) p;  // work out original
  porig = porig - *(porig-1);                 // by subtracting padding
  free (porig);                               // then free that
}

const char* llvm_scheme_ff_get_name(foreign_func ff) 
{
   return (LLVM_SCHEME_FF_MAP[ff]).c_str();
}

void llvm_scheme_ff_set_name(foreign_func ff,const char* name) 
{
  LLVM_SCHEME_FF_MAP[ff] = std::string(name);
  return;
}

// LLVM RUNTIME ERROR
void llvm_runtime_error(int error,void* arg)
{
  ascii_error();
  switch(error){
  case 1:
    printf("LLVM zptr_copy - invalid zptr! %p\n",arg);
    break;    
  default:
    break;
  }
  ascii_normal();
  return;
}

//////////////////////////////////////////////////////////////////
// this whole zone section should 
// all be thread safe of course
// but currently isn't!
// FIX ME!!

thread_local llvm_zone_stack* tls_llvm_zone_stack = 0;
thread_local uint64_t tls_llvm_zone_stacksize = 0;
thread_local llvm_zone_t* tls_llvm_callback_zone = 0;

llvm_zone_t* llvm_pop_zone_stack()
{
    llvm_zone_stack* stack = llvm_threads_get_zone_stack();
    if (unlikely(!stack)) {
#if DEBUG_ZONE_STACK      
      printf("TRYING TO POP A ZONE FROM AN EMPTY ZONE STACK\n");
#endif
      return nullptr;
    }
    llvm_zone_t* head = stack->head;
    llvm_zone_stack* tail = stack->tail;
#if DEBUG_ZONE_STACK    
    llvm_threads_dec_zone_stacksize();
    if (!tail) {
      printf("%p: popping zone %p:%lld from stack with no tail\n",stack,head,head->size);
    } else {
      printf("%p: popping new zone %p:%lld back to old zone %p:%lld\n",stack,head,head->size,tail->head,tail->head->size);
    }
#endif
    free(stack);
    llvm_threads_set_zone_stack(tail);
    return head;
}

void llvm_zone_destroy(llvm_zone_t* zone)
{
  #if DEBUG_ZONE_ALLOC  
    printf("DestroyZone: %p:%p:%lld:%lld\n",zone,zone->memory,zone->offset,zone->size);
  #endif
    if(zone->memories != NULL) llvm_zone_destroy(zone->memories);
    // immediate zeroing for debug purposes!
    memset(zone->memory,0,zone->size);
    free(zone->memory);    
    free(zone);
    return;
}

void llvm_zone_print(llvm_zone_t* zone)
{
  auto tmp(zone);
  auto total_size(zone->size);
  int64_t segments(1);
  while (tmp->memories) {
    tmp = tmp->memories;
    total_size += tmp->size;
    segments++;
  }
  printf("<MemZone(%p) size(%" PRId64 ") free(%" PRId64 ") segs(%" PRId64 ")>",zone,total_size,(zone->size - zone->offset),segments);
  return;
}

void* llvm_zone_malloc(llvm_zone_t* zone, uint64_t size)
{
    alloc_mutex.lock();
#if DEBUG_ZONE_ALLOC
    printf("MallocZone: %p:%p:%lld:%lld:%lld\n",zone,zone->memory,zone->offset,zone->size,size);
#endif
    size += LLVM_ZONE_ALIGN; // for storing size information
    if (unlikely(zone->offset + size >= zone->size))
    {
#if EXTENSIBLE_ZONES // if extensible_zones is true then extend zone size by zone->size
    int old_zone_size = zone->size;
    int iszero = (zone->size == 0) ? 1 : 0;
    if(size > zone->size) zone->size = size;
    zone->size = zone->size * 2; // keep doubling zone size for each new allocation
    if(zone->size < 1024) zone->size = 1024; // allocate a min size of 1024 bytes
    llvm_zone_t* newzone = llvm_zone_create(zone->size);
    void* tmp = newzone->memory;
    if(iszero == 1) { // if initial zone is 0 - the replace don't extend
      zone->memory = tmp;
      free(newzone);
    } else {
      // printf("adding new memory %p:%lld to existing %p:%lld\n",newzone,newzone->size,zone,zone->size);
      newzone->memories = zone->memories;
      newzone->memory = zone->memory;
      newzone->size = old_zone_size;
      zone->memory = tmp;
      zone->memories = newzone;
    }
    llvm_zone_reset(zone);
#elif LEAKY_ZONES       // if LEAKY ZONE is TRUE then just print a warning and just leak the memory
        printf("\nZone:%p size:%lld is full ... leaking %lld bytes\n",zone,zone->size,size);
      printf("Leaving a leaky zone can be dangerous ... particularly for concurrency\n");
      fflush(NULL);
        return malloc((size_t)size);  // TODO: what about the stored size????
    #else
	printf("\nZone:%p size:%lld is full ... exiting!\n",zone,zone->size,size);
        fflush(NULL);
	exit(1);
#endif
    }
    size = (size + LLVM_ZONE_ALIGNPAD) & ~LLVM_ZONE_ALIGNPAD;
    auto newptr = reinterpret_cast<void*>(reinterpret_cast<char*>(zone->memory) + zone->offset);
    memset(newptr, 0, size); // clear memory
    newptr = reinterpret_cast<char*>(newptr) + LLVM_ZONE_ALIGN; // skip past size
    *(reinterpret_cast<uint64_t*>(newptr) - 1) = size;
    zone->offset += size; 
    alloc_mutex.unlock();
    return newptr;
}

void llvm_zone_mark(llvm_zone_t* zone)
{
    zone->mark = zone->offset;
}

uint64_t llvm_zone_mark_size(llvm_zone_t* zone)
{
    return zone->offset - zone->mark;
}

void llvm_zone_ptr_set_size(void* ptr, uint64_t size)
{
    *(reinterpret_cast<uint64_t*>(ptr) - 1) = size;
}

uint64_t llvm_zone_ptr_size(void* ptr)
{
    // return ptr size from alloc map
    return *(reinterpret_cast<uint64_t*>(ptr) - 1);
}

bool llvm_zone_copy_ptr(void* ptr1, void* ptr2)
{
    uint64_t size1 = llvm_zone_ptr_size(ptr1);
    uint64_t size2 = llvm_zone_ptr_size(ptr2);

    if (unlikely(size1 != size2)) {
  //printf("Bad LLVM ptr copy - size mismatch setting %p:%lld -> %p:%lld\n",ptr1,size1,ptr2,size2); 
      return 1;
    }
    if (unlikely(!size1)) {
  //printf("Bad LLVM ptr copy - size mismatch setting %p:%lld -> %p:%lld\n",ptr1,size1,ptr2,size2); 
      return 1;
    }
    //printf("zone_copy_ptr: %p,%p,%lld,%lld\n",ptr2,ptr1,size1,size2);
    memcpy(ptr2, ptr1, size1);
    return 0;		
}

bool llvm_ptr_in_zone(llvm_zone_t* zone, void* ptr)
{
    while (unlikely(zone && (ptr < zone->memory || ptr >= reinterpret_cast<char*>(zone->memory) + zone->size))) {
      zone = zone->memories;
    }
    return zone;
}

bool llvm_ptr_in_current_zone(void* ptr)
{
    return llvm_ptr_in_zone(llvm_peek_zone_stack(), ptr);
}

extemp::CM* FreeWithDelayCM = mk_cb(extemp::SchemeFFI::I(),extemp::SchemeFFI,freeWithDelay);
void free_after_delay(char* dat, double delay)
{
    //printf("freeWithDelay %p\n",zone);
    extemp::CM* cb = FreeWithDelayCM; 
    extemp::Task<char*>* task = new extemp::Task<char*>(extemp::UNIV::TIME+delay,44100,cb,dat);
    extemp::TaskScheduler::I()->add(task);
}

extemp::CM* DestroyMallocZoneWithDelayCM = mk_cb(extemp::SchemeFFI::I(),extemp::SchemeFFI,destroyMallocZoneWithDelay);
void llvm_destroy_zone_after_delay(llvm_zone_t* zone, uint64_t delay)
{
    // printf("destroyWithDelay %p\n",zone);
    extemp::CM* cb = DestroyMallocZoneWithDelayCM;
    extemp::Task<llvm_zone_t*>* task = new extemp::Task<llvm_zone_t*>(extemp::UNIV::TIME+delay,44100,cb,zone);
    extemp::TaskScheduler::I()->add(task);
}

void llvm_schedule_callback(long long time, void* dat)
{
  //printf("scheduled callback %lld\n",time);
  extemp::SchemeProcess* proc = extemp::SchemeProcess::I(); //extemp::SchemeProcess::I()->extemporeCallback(time,dat);

  uint64_t current_time = time; //task->getStartTime();
  uint64_t duration = 1000000000; //task->getDuration();
  extemp::TaskScheduler::I()->addTask(current_time, duration, proc->getExtemporeCallback(), dat, 0, true);
  return;
}

void* llvm_get_function_ptr(char* fname)
{
  using namespace llvm;
  
  llvm::Function* func = extemp::EXTLLVM::I()->getFunction(fname);        
  if(func == NULL)
    {
      return NULL;
    }
  // has the function been loaded somewhere else, e.g. dlsym
  void* p = extemp::EXTLLVM::I()->EE->getPointerToGlobalIfAvailable(func);
  if(p==NULL) // look for it as a JIT-compiled function
    p = extemp::EXTLLVM::I()->EE->getPointerToFunction(func);
  if(p==NULL) {
    return NULL;
  }
  return p;
}

char* extitoa(int64_t val) {
	/*
  int base = 10;
  static char buf[32] = {0};        
  int i = 30;        
  for(; val && i ; --i, val /= base)        
    buf[i] = "0123456789abcdef"[val % base]; 
	*/
  static char buf[32] = {0};
  sprintf(buf,"%" PRId64,val);
  return buf;//&buf[i+1];        
}

void llvm_send_udp(char* host, int port, void* message, int message_length)
{
  int length = message_length;
  int ret = 0;
  char* ptr;

#ifdef EXT_BOOST
  boost::asio::io_service io_service;
  boost::asio::ip::udp::resolver::iterator end;
  boost::asio::ip::udp::resolver resolver(io_service);
  std::stringstream ss;
  ss << port;
  boost::asio::ip::udp::resolver::query newQuery(boost::asio::ip::udp::v4(),host, ss.str());
  boost::asio::ip::udp::resolver::iterator iter = resolver.resolve(newQuery);

  boost::asio::ip::udp::endpoint sa = *iter;
#else
  struct sockaddr_in sa;
  struct hostent* hen; /* host-to-IP translation */

  /* Address resolution stage */
  hen = gethostbyname(host);
  if (!hen) {
    printf("OSC Error: Could no resolve host name\n");
    return;			
  }

  memset(&sa, 0, sizeof(sa));

  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  memcpy(&sa.sin_addr.s_addr, hen->h_addr_list[0], hen->h_length);
#endif		


#ifdef EXT_BOOST
  boost::asio::ip::udp::socket* fd = 0;
#else
  int fd = 0;
#endif

#ifdef EXT_BOOST
  int err = 0;
  boost::asio::io_service service;
  boost::asio::ip::udp::socket socket(service);
  socket.open(boost::asio::ip::udp::v4());
  socket.send_to(boost::asio::buffer(message, length), sa);
#else
  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);			
  int err = sendto(fd, message, length, 0, (struct sockaddr*)&sa, sizeof(sa));
  close(fd);
#endif
  if(err < 0)
    {
      if(err == EMSGSIZE) {
	printf("Error: OSC message too large: UDP 8k message MAX\n");
      }else{
	printf("Error: Problem sending OSC message %d\n",err);
      }			

    }

  return;
}


long long llvm_get_next_prime(long long start)
{
    long long  how_many = start+100000;
    long long  *array = (long long*) calloc(how_many, sizeof(long long));
    long long  i, prime, multiple;
    /*  mark each int as potentially prime */
    for (i=0; i<how_many; i++)
	array[i] = 1;
    /* special cases: 0, 1 not considered prime */
    array[0] = array[1] = 0;
    /* foreach starting prime, mark every multiple as non-prime */
    prime = 0;
    while (1) {
	/* skip non-primes to find first prime */
	for (; (prime < how_many) && (!array[prime]); ++prime)
	    continue;
	if (prime >= how_many)
	    break;
	for (multiple=2*prime; multiple<how_many; multiple+=prime) {
	    array[multiple] = 0;
	}
	++prime;
    }
    /* Now that we have marked all multiple of primes as non-prime, */
    /* print the remaining numbers that fell through the sieve, and */
    /* are thus prime */
    for (i=start+1; i<how_many; i++) {
	if(array[i]) return i;
    }
    return -1;
}

/////////////////////////////////////////////
//
// some native threading support xtlang
//
/////////////////////////////////////////////

void* thread_fork(void*(*start_routine)(void*), void* args) {
        auto thread = new extemp::EXTThread(start_routine, args, "fork");
        int result = thread->start();

#ifdef _EXTTHREAD_DEBUG_
	if (result)
	{
		std::cerr << "Error creating thread: " << result << std::endl;
	}
#endif

	return static_cast<void*>(thread);
}

int thread_join(void* thread) {
	return static_cast<extemp::EXTThread*>(thread)->join();
}

int thread_kill(void* thread) {
	return static_cast<extemp::EXTThread*>(thread)->kill();
}

int thread_equal(void* thread1, void* thread2) {
	return static_cast<extemp::EXTThread*>(thread1)->isEqualTo(static_cast<extemp::EXTThread*>(thread2));
}

int thread_equal_self(void* thread1) {
	return static_cast<extemp::EXTThread*>(thread1)->isCurrentThread(); 
}

void* thread_self() {	
	return static_cast<void*>(extemp::EXTThread::activeThread());
}

// return value is number of nanosecs sleep missed by
int64_t thread_sleep(int64_t secs, int64_t nanosecs) {
#ifdef _WIN32
  std::this_thread::sleep_for(std::chrono::seconds(secs) +
                              std::chrono::nanoseconds(nanosecs));
  return 0;
#else
  struct timespec a, b;
  a.tv_sec = secs;
  a.tv_nsec = nanosecs;
  int rval = nanosleep(&a,&b);
  if(rval == 0) {
    return 0;
  } else if (errno == EINTR) {
    return b.tv_nsec;
  } else {
    return -1;
  }
#endif  
}

void* mutex_create() {
#ifdef _WIN32
  return NULL;
#else
  pthread_mutex_t* mutex = (pthread_mutex_t*) malloc(sizeof(pthread_mutex_t));
  int res = pthread_mutex_init(mutex,NULL);
  if(res == 0) return mutex;
  else return NULL;
#endif
}

int mutex_destroy(void* mutex) {
#ifdef _WIN32
  return NULL;
#else
  pthread_mutex_t* m = (pthread_mutex_t*) mutex;
  return pthread_mutex_destroy(m);
#endif
}

int mutex_lock(void* mutex) {
#ifdef _WIN32
  return -1;
#else
  pthread_mutex_t* m = (pthread_mutex_t*) mutex;
  return pthread_mutex_lock(m);
#endif
}

int mutex_unlock(void* mutex) {
#ifdef _WIN32
  return -1;
#else
  pthread_mutex_t* m = (pthread_mutex_t*) mutex;
  return pthread_mutex_unlock(m);
#endif
}

int mutex_trylock(void* mutex) {
#ifdef _WIN32
  return -1;
#else
  pthread_mutex_t* m = (pthread_mutex_t*) mutex;
  return pthread_mutex_trylock(m);
#endif
}



/////////////////////////////////////////////////
// This added for dodgy continuations support
// ucontext_t* llvm_make_ucontext()
// {
//   ucontext_t* ctx = (ucontext_t*) malloc(sizeof(ucontext_t));
//   ctx->uc_stack.ss_sp   = (void*) malloc(1024*1024); //iterator_stack;
//   ctx->uc_stack.ss_size = 1024*1024;
//   return ctx;
// }

// ucontext_t* llvm_scheme_process_ucontext()
// {
//   extemp::SchemeProcess* proc = extemp::SchemeProcess::I(); //extemp::SchemeProcess::I()->extemporeCallback(time,dat);
//   ucontext_t* ctx = proc->getContext();
//   return ctx;
// }
///////////////////////////////////////////////////

// these are helpers for runtime debugging in llvm
void llvm_print_pointer(void* ptr)
{
    printf("llvm:ptr:>%p -- %" PRId64 "\n",ptr,*((int64_t*)ptr));
    return;
}

void llvm_print_i32(int32_t num)
{
    printf("llvm:i32:>%d\n",num);
    return;
}

void llvm_print_i64(int64_t num)
{
    printf("llvm:i64:>%" PRId64 "\n",num);
    return;
}

void llvm_print_f32(float num)
{
    printf("llvm:f32:>%f\n",num);
    return;
}

void llvm_print_f64(double num)
{
    printf("llvm:f64:>%f\n",num);
    return;
}

int64_t llvm_now()
{
    return extemp::UNIV::TIME;
}

// double llvm_cos(double x) { return cos(x); }
// double llvm_sin(double x) { return sin(x); }
double llvm_tan(double x) { return tan(x); }
double llvm_cosh(double x) { return cosh(x); }
double llvm_tanh(double x) { return tanh(x); }
double llvm_sinh(double x) { return sinh(x); }
double llvm_acos(double x) { return acos(x); }
double llvm_asin(double x) { return asin(x); }
double llvm_atan(double x) { return atan(x); }
double llvm_atan2(double x,double y) { return atan2(x,y); }
// double llvm_ceil(double x) { return ceil(x); }
// double llvm_floor(double x) { return floor(x); }
// double llvm_exp(double x) { return exp(x); }
// double llvm_fmod(double x,double y) { return fmod(x,y); }
// double llvm_pow(double x,double y) { return pow(x,y); }
// double llvm_log(double x) { return log(x); }
// double llvm_log2(double x) { return log2(x); }
// double llvm_log10(double x) { return log10(x); }
// double llvm_sqrt(double x) { return sqrt(x); }
// double llvm_fabs(double x) { return fabs(x); }

// these shouldn't ever be large, so it should be ok to cast to signed
// int for returning into xtlang (which prefers signed ints). I hope
// this doesn't come back to bite me one day.
int32_t llvm_samplerate() { return (int32_t)extemp::UNIV::SAMPLERATE; }
int32_t llvm_frames() { return (int32_t)extemp::UNIV::FRAMES; }
int32_t llvm_channels() { return (int32_t)extemp::UNIV::CHANNELS; }
int32_t llvm_in_channels() { return (int32_t)extemp::UNIV::IN_CHANNELS; }

double imp_randd()
{
#ifdef EXT_BOOST
  return extemp::UNIV::random();
#else
    return (double)rand()/(double)RAND_MAX;
#endif
}

float imp_randf()
{
#ifdef EXT_BOOST
  return extemp::UNIV::random();
#else
    return (float)rand()/(float)RAND_MAX;
#endif
}

int64_t imp_rand1_i64(int64_t a)
{
#ifdef EXT_BOOST
  return (int64_t) extemp::UNIV::random()*a;
#else
  return (int64_t) (((double)rand()/(double)RAND_MAX)*(double)a);
#endif
}

int64_t imp_rand2_i64(int64_t a, int64_t b)
{
#ifdef EXT_BOOST
  return (int64_t) a+(extemp::UNIV::random()*((double)b-(double)a));
#else
  return (int64_t) a+(((double)rand()/(double)RAND_MAX)*((double)b-(double)a));
#endif
}

int32_t imp_rand1_i32(int32_t a)
{
#ifdef EXT_BOOST
  return (int32_t) extemp::UNIV::random()*(double)a;
#else
  return (int32_t) (((double)rand()/(double)RAND_MAX)*(double)a);
#endif
}

int32_t imp_rand2_i32(int32_t a, int32_t b)
{
#ifdef EXT_BOOST
  return (int32_t) a+(extemp::UNIV::random()*((double)b-(double)a));
#else
  return (int32_t) a+(((double)rand()/(double)RAND_MAX)*((double)b-(double)a));
#endif
}

double imp_rand1_d(double a)
{
#ifdef EXT_BOOST
  return extemp::UNIV::random()*a;
#else
  return ((double)rand()/(double)RAND_MAX)*a;
#endif
}

double imp_rand2_d(double a, double b)
{
#ifdef EXT_BOOST
  return a+(extemp::UNIV::random()*(b-a));
#else
  return a+(((double)rand()/(double)RAND_MAX)*(b-a));
#endif
}

float imp_rand1_f(float a)
{
#ifdef EXT_BOOST
  return extemp::UNIV::random()*a;
#else
  return ((double)rand()/(double)RAND_MAX)*a;
#endif
}

float imp_rand2_f(float a, float b)
{
#ifdef EXT_BOOST
  return a+((float)extemp::UNIV::random()*(b-a));
#else
  return a+(((float)rand()/(float)RAND_MAX)*(b-a));
#endif
}


///////////////////////////////////

///////////////////////////////////////////////////////////////////////
// This here for Extempore Compiler Runtime.
// This is temporary and needs to replaced with something sensible!
struct closure_address_table
{
    uint64_t id; 
    char* name;
    uint32_t offset;
    char* type;
    struct closure_address_table* next;
};

struct closure_address_table* get_address_table(const char* name, closure_address_table* table)
{
  while(table)
    {
      if(strcmp(table->name,name)) return table;
      table = table->next;
    }
  printf("Unable to locate %s in closure environment a\n",name);
  return 0;
}

uint32_t get_address_offset(uint64_t id, closure_address_table* table)
{
    while(table)
    {
      // printf("%p name: %s\ntablename: %s\n\n", name, name, table->name);
      if(table->id == id) {
        // printf("in %s returning offset %d from %s\n",table->name,table->offset,name);
        return table->offset;
      }
      table = table->next;
    }
    printf("Unable to locate %" PRIu64 " in closure environment b\n",id);
    return 0;
}

char* get_address_type(uint64_t id, closure_address_table* table)
//char* get_address_type(const char* name, closure_address_table* table)
{
    while(table)
    {
      if(table->id == id) {
        return table->type;
      }
      table = table->next;
    }
    printf("Unable to locate id in closure environment c\n");
    return 0;  
}

bool check_address_exists(uint64_t id, closure_address_table* table)
{
  while(table)
    {
      if(table->id == id) {
        return true;
      }
      table = table->next;
    }
  return false;  
}

bool check_address_type(uint64_t id, closure_address_table* table, const char* type)
{
  while(table)
    {
      if(table->id == id) {
        if((strcmp(table->type,type)!=0) && (strcmp("{i8*, i8*, void (i8*, i8*)*}**",type)!=0)) {
          printf("Runtime Type Error: bad type %s for %s. Should be %s\n",type,table->name,table->type);
          return 0;
        }else{
          return 1;
        }
      }
      table = table->next;
    }
  printf("Unable to locate id in closure environment type: %s d\n",type);
  return 0;
}

struct closure_address_table* new_address_table()
{
    return 0; // NULL for empty table
}
 
struct closure_address_table* add_address_table(llvm_zone_t* zone, char* name, uint32_t offset, char* type, int alloctype, struct closure_address_table* table)
{
  struct closure_address_table* t = NULL;
  if(alloctype == 1) {
    t = (struct closure_address_table*) malloc(sizeof(struct closure_address_table));
  /* }  else if(alloctype == 2) {
#ifdef _WIN32
    t = (struct closure_address_table*) _alloca(sizeof(struct closure_address_table));
#else
    t = (struct closure_address_table*) alloca(sizeof(struct closure_address_table));
#endif */
  } else {
    t = (struct closure_address_table*) llvm_zone_malloc(zone,sizeof(struct closure_address_table));
  }
    t->id = string_hash((unsigned char*) name);
  t->name = name;
  t->offset = offset;
  t->type = type;
  t->next = table;
  return t;
}

bool llvm_check_valid_dot_symbol(scheme* sc, char* symbol) {
  char c[1024];
  auto pos(strchr(symbol, '.'));
  if (!pos) {
    //printf("Eval error: not valid dot syntax\n");
    return false;
  }
  strncpy(c, symbol, pos - symbol);
  pointer x = find_slot_in_env(sc, sc->envir, mk_symbol(sc, c), 1);
  if (x == sc->NIL) {
    return false;
  }
  strcat(c, "_xtlang_name");
  pointer y = find_slot_in_env(sc, sc->envir, mk_symbol(sc, c), 1);
  return y != sc->NIL;
}
/*
    //llvm::Module* M = extemp::EXTLLVM::I()->M;
    std::string funcname(a);
    std::string getter("_getter");
    //llvm::Function* func = M->getFunction(funcname+getter);
    llvm::Function* func = extemp::EXTLLVM::I()->getFunction(funcname+getter);
    if(func) {
      return true;
    }else{
      //printf("Eval error: No compiler match for %s\n",symbol);
      return false; 
    }
  }
  }
*/

#define strvalue(p)      ((p)->_object._string._svalue)
pointer llvm_scheme_env_set(scheme* _sc, char* sym)
{
  using namespace llvm; 
  char fname[256];
  char tmp[256];
  char vname[256];
  char tname[256];
  
  char c[1024];
  memset(c,0,1024);
  const char* d = "_xtlang_name";
  
  if(!(rsplit((char*)"\\.",sym, (char*) fname, (char*) tmp))) {
    printf("Error attempting to set environment variable in closure bad split %s\n",sym);
    return _sc->F;  
  }
  if(!rsplit((char*)":",tmp, (char*) vname,(char*) tname)) {
    memset(tname, 0, 256);
    memset(vname, 0, 256);
    memcpy(vname, tmp, 256);
  }
  strcat(c,fname);
  strcat(c,d);
  pointer xtlang_f_name = find_slot_in_env(_sc,_sc->envir,mk_symbol(_sc,c),1);
  char* xtlang_name = strvalue(pair_cdr(xtlang_f_name));
  //printf("in llvm scheme env set %s.%s:%s  xtlang:%s\n",fname,vname,tname,xtlang_name);
  uint64_t id = string_hash((unsigned char*)vname);
  // Module* M = extemp::EXTLLVM::I()->M;
  std::string funcname(xtlang_name);
  std::string getter("_getter");
  //llvm::Function* func = M->getFunction(funcname+getter); //std::string(string_value(pair_car(args))));
  llvm::Function* func = extemp::EXTLLVM::I()->getFunction((funcname+getter).c_str());
  if(func == 0) {
    printf("Error: no matching function for %s.%s\n",fname,vname);
    return _sc->F; 
  }
  
  void*(*p)() = (void*(*)()) extemp::EXTLLVM::I()->EE->getPointerToGlobalIfAvailable(func);
  if(p==NULL){
     p = (void*(*)()) extemp::EXTLLVM::I()->EE->getPointerToFunction(func);
  }else if(p==NULL) {
    printf("Error attempting to set environment variable in closure %s.%s\n",fname,vname);
    return _sc->F;
  }
  
  size_t*** closur = (size_t***) p();
  size_t** closure = *closur;
  //uint32_t** closure = (uint32_t**) cptr_value(pair_car(args));
  closure_address_table* addy_table = (closure_address_table*) *(closure+0);
  // check address exists
  if(!check_address_exists(id, addy_table)) {
    ascii_error();
    printf("RunTime Error:");
    ascii_normal();
    printf(" slot");
    ascii_warning();
    printf(" %s.%s ",fname,vname);
    ascii_normal();
    printf("does not exist!\n");
    ascii_default();
    return _sc->F;
  }
  char* eptr = (char*) *(closure+1);
  char* type = get_address_type(id,addy_table);
  uint32_t offset = get_address_offset(id,addy_table);

  //printf("type: %s  offset: %d\n",type, offset);

  pointer value = 0;
  if(_sc->args == _sc->NIL) {
    //value = 0;
    value = _sc->NIL;
  } else {   
    value = pair_car(_sc->args);
  }

  if(strcmp(type,"i32")==0) {
    int32_t** ptr = (int32_t**) (eptr+offset);
    if(value == _sc->NIL) {
      return mk_integer(_sc, **ptr);
    } else {
      **ptr = (int32_t) ivalue(value);
      return _sc->T;
    }
  }else if(strcmp(type,"i64")==0){
    uint64_t** ptr = (uint64_t**) (eptr+offset);
    if(value == _sc->NIL) {
      return mk_integer(_sc, **ptr);
    } else {
      **ptr = ivalue(value);
      return _sc->T;
    }        
  }else if(strcmp(type,"float") == 0){
    float** ptr = (float**) (eptr+offset);
    if(value == _sc->NIL) {
      return mk_real(_sc, **ptr);
    } else {
      **ptr = rvalue(value);
      return _sc->T;
    }            
  }else if(strcmp(type,"double")==0){
    double** ptr = (double**) (eptr+offset);
    if(value == _sc->NIL) {
      return mk_real(_sc, **ptr);
    } else {
      **ptr = rvalue(value);
      return _sc->T;
    }            
  }else{ // else pointer type
    char*** ptr = (char***) (eptr+offset);
    if(value == _sc->NIL) {      
      return mk_cptr(_sc, (void*) **ptr);
    } else {
      **ptr = (char*) cptr_value(value);
      //printf("Unsuported type for closure environment set\n");
      return _sc->T;
    }
  }
  // shouldn't get to here 
  return _sc->F;
}


char* llvm_disassemble(const unsigned char* code,int syntax)
{
        int x64 = 1;
        size_t code_size = 1024 * 100;
        //std::string ArchName = (x64 > 0) ? "x86-64" : "x86";
        //std::string TripleName = llvm::Triple::normalize(ArchName);
        //llvm::Triple Triple(TripleName);
        std::string Error;
        llvm::TargetMachine *TM = extemp::EXTLLVM::I()->EE->getTargetMachine();
        llvm::Triple Triple = TM->getTargetTriple();                 
        const llvm::Target TheTarget = TM->getTarget();
        std::string TripleName = Triple.getTriple();

        //const llvm::Target* TheTarget = llvm::TargetRegistry::lookupTarget(ArchName,Triple,Error);
        const llvm::MCRegisterInfo* MRI(TheTarget.createMCRegInfo(TripleName));
        const llvm::MCAsmInfo* AsmInfo(TheTarget.createMCAsmInfo(*MRI,TripleName));
        const llvm::MCSubtargetInfo* STI(TheTarget.createMCSubtargetInfo(TripleName,"",""));
        const llvm::MCInstrInfo* MII(TheTarget.createMCInstrInfo());        
        //const llvm::MCInstrAnalysis* MIA(TheTarget->createMCInstrAnalysis(MII->get()));
        llvm::MCContext Ctx(AsmInfo, MRI, nullptr);
        llvm::MCDisassembler* DisAsm(TheTarget.createMCDisassembler(*STI,Ctx));        
        llvm::MCInstPrinter* IP(TheTarget.createMCInstPrinter(Triple,syntax,*AsmInfo,*MII,*MRI)); //,*STI));
        IP->setPrintImmHex(true);
        IP->setUseMarkup(true);
        uint64_t MemoryAddr = 0;
        uint64_t Size = code_size;
        uint64_t Start = 0;
        uint64_t End = code_size;
        std::string out_str;
        llvm::raw_string_ostream OS(out_str);
        llvm::ArrayRef<uint8_t> mem(code,code_size);
        uint64_t size;
        uint64_t index;
        OS << "\n";
        for (index = 0; (index < code_size); index += size) {
          llvm::MCInst Inst;
          //printf("%p index: %lld\n", DisAsm, (long long) index);
          //if (Disassmbler->getInstruction(Inst, size, *BufferMObj, index, llvm::nulls(), llvm::nulls())) {
          if (DisAsm->getInstruction(Inst, size, mem.slice(index), index, llvm::nulls(), llvm::nulls())) {
            if((*(size_t *)(code + index)) > 0) {
              OS.indent(4);
              OS.write("0x", 2);
              OS.write_hex((size_t)code + index);
              OS.write(": ", 2);  // 0x", 4);
              //OS.write_hex(*(size_t *)(code + index));
              IP->printInst(&Inst,OS,"",*STI);
              OS << "\n";
            }else{
              break;
            }
          } else {
            if (size == 0)
              size = 1;  // skip illegible bytes
          }
        }
        //OS << "\n";
        std::string tmp = OS.str();
        //std::cout << "TEST:" << std::endl << tmp.c_str() << std::endl << std::endl;
        char* tmpstr = (char*) malloc(tmp.length()+1);
        strcpy(tmpstr,tmp.c_str());
        return tmpstr;
}



namespace extemp {
	
    EXTLLVM EXTLLVM::SINGLETON;
    int64_t EXTLLVM::LLVM_COUNT = 0l;
    bool EXTLLVM::OPTIMIZE_COMPILES = false;
    bool EXTLLVM::VERIFY_COMPILES = true;
	
    EXTLLVM::EXTLLVM()
    {
	//printf("making llvm !!!!!!!!!!!!!!!!!!\n");
        alloc_mutex.init();
	M = 0;
	MP = 0;
	EE = 0;
#ifdef EXT_MCJIT
  MM = 0;
#endif
	//initLLVM();
    }
  EXTLLVM::~EXTLLVM() {}

#ifdef EXT_MCJIT  
    uint64_t EXTLLVM::getSymbolAddress(const std::string& name) {      
      return MM->getSymbolAddress(name);
    }
#endif

  void EXTLLVM::initLLVM()
  {
    if(M == 0) { // Initalize Once Only (not per scheme process)

      llvm::TargetOptions Opts;
      Opts.GuaranteedTailCallOpt = true;
      Opts.UnsafeFPMath = false;

      llvm::InitializeNativeTarget();
      llvm::InitializeNativeTargetAsmPrinter();
      LLVMInitializeX86Disassembler();      
      
      llvm::LLVMContext &context = llvm::getGlobalContext();
      //llvm::IRBuilder<> theBuilder(context);

      // Make the module, which holds all the code.
      std::unique_ptr<llvm::Module> module = llvm::make_unique<llvm::Module>("xtmmodule_0", context);

      M = module.get();
      addModule(M);

      if (!extemp::UNIV::ARCH.empty()) M->setTargetTriple(extemp::UNIV::ARCH);

      // Build engine with JIT
      llvm::EngineBuilder factory(std::move(module));
      factory.setEngineKind(llvm::EngineKind::JIT);
      // factory.setAllocateGVsWithCode(false);
      factory.setTargetOptions(Opts);
#ifdef EXT_MCJIT
      std::unique_ptr<llvm::SectionMemoryManager> MM = llvm::make_unique<llvm::SectionMemoryManager>();
      factory.setMCJITMemoryManager(std::move(MM));
#else          
      factory.setUseMCJIT(false);
#endif
#ifdef _WIN32
      if(!extemp::UNIV::ATTRS.empty()) factory.setMAttrs(extemp::UNIV::ATTRS);
      if(!extemp::UNIV::CPU.empty()) factory.setMCPU(extemp::UNIV::CPU.front());
      llvm::TargetMachine* tm = factory.selectTarget();
#else
      factory.setOptLevel(llvm::CodeGenOpt::Aggressive);
      llvm::Triple triple(llvm::sys::getProcessTriple());           
      std::string cpu = llvm::sys::getHostCPUName();
      if(!extemp::UNIV::CPU.empty()) cpu = extemp::UNIV::CPU.front();
      llvm::StringMap<bool> HostFeatures;
      llvm::sys::getHostCPUFeatures(HostFeatures);
      llvm::SmallVector<std::string,10> lattrs;
      for( llvm::StringMap<bool>::const_iterator it = HostFeatures.begin(); it != HostFeatures.end(); it++  )
        {
          std::string att = it->getValue() ? it->getKey().str() :
            std::string("-") + it->getKey().str();
          lattrs.append( 1, att );
        }
      if(!extemp::UNIV::ATTRS.empty()) {
        lattrs.clear();
        for(int i=0;i<extemp::UNIV::ATTRS.size();i++) {
          lattrs.append(1, extemp::UNIV::ATTRS[i]);
        }
      }          
      
      llvm::TargetMachine* tm = factory.selectTarget(triple,"",cpu,lattrs);
#endif // _WIN32
      EE = factory.create(tm);
      EE->DisableLazyCompilation(true);

      ascii_normal();
      std::cout << "ARCH           : " << std::flush;
      ascii_info();
      std::cout << std::string(tm->getTargetTriple().normalize()) << std::endl;
#ifdef _WIN32
      if(!std::string(tm->getTargetFeatureString()).empty())
#else
      if(!std::string(tm->getTargetCPU()).empty())
#endif
        {
          ascii_normal();
          std::cout << "CPU            : " << std::flush;
          ascii_info();
          std::cout << std::string(tm->getTargetCPU()) << std::endl;
        }
      if(!std::string(tm->getTargetFeatureString()).empty())
        {
          ascii_normal();
          std::cout << "ATTRS          : " << std::flush;

          const char* data = tm->getTargetFeatureString().data();

          for (int i = 0; i < strlen(data); i++) {
            switch (data[i]) {
            case '+': {
              ascii_info();
              break;
            }
            case '-': {
              ascii_error();
              break;
            }
            case ',': {
              ascii_normal();
              break;
            }
            }
            printf("%c", data[i]);
          }
          std::cout << std::endl;
        }
      ascii_normal();
      std::cout << "LLVM           : " << std::flush;
      ascii_info();
      std::cout << LLVM_VERSION_STRING;
#ifdef EXT_MCJIT
      std::cout << " MCJIT" << std::endl;
#else
      std::cout << " JIT" << std::endl;
#endif          
      ascii_normal();
          

			
	    //EE = llvm::EngineBuilder(M).create();
            PM_NO = new llvm::legacy::PassManager();
            PM_NO->add(llvm::createAlwaysInlinerPass());
	    PM = new llvm::legacy::PassManager();
#if 1
            PM->add(llvm::createAggressiveDCEPass());
            PM->add(llvm::createAlwaysInlinerPass());
            PM->add(llvm::createArgumentPromotionPass());
            PM->add(llvm::createCFGSimplificationPass());
            PM->add(llvm::createDeadStoreEliminationPass());
            PM->add(llvm::createFunctionAttrsPass());
            PM->add(llvm::createFunctionInliningPass());\
            PM->add(llvm::createGVNPass(true));
            PM->add(llvm::createIndVarSimplifyPass());
            PM->add(llvm::createInstructionCombiningPass());
            PM->add(llvm::createJumpThreadingPass());
            PM->add(llvm::createLICMPass());
            PM->add(llvm::createLoopDeletionPass());
            PM->add(llvm::createLoopRotatePass());
            PM->add(llvm::createLoopUnrollPass());
            PM->add(llvm::createMemCpyOptPass());
            PM->add(llvm::createPromoteMemoryToRegisterPass());
            PM->add(llvm::createReassociatePass());
            PM->add(llvm::createScalarReplAggregatesPass());
            PM->add(llvm::createSCCPPass());
            PM->add(llvm::createTailCallEliminationPass());
#else
	    //PM->add(new llvm::TargetData(*EE->getTargetData()));
      // PM->add(new llvm::DataLayout(*(EE->getDataLayout())));

      PM->add(llvm::createBasicAliasAnalysisPass());   //new   
      // promote allocs to register
      PM->add(llvm::createPromoteMemoryToRegisterPass());
	    // Do simple "peephole" optimizations and bit-twiddling optzns.
	    PM->add(llvm::createInstructionCombiningPass());
	    // Reassociate expressions.
	    PM->add(llvm::createReassociatePass());
	    // Eliminate Common SubExpressions.
	    PM->add(llvm::createGVNPass());
	    // Function inlining
	    PM->add(llvm::createFunctionInliningPass());
            PM->add(llvm::createAlwaysInlinerPass());
	    // loop invariants
	    PM->add(llvm::createLICMPass());
	    // vars
	    PM->add(llvm::createIndVarSimplifyPass());
	    // Simplify the control flow graph (deleting unreachable blocks, etc).
	    PM->add(llvm::createCFGSimplificationPass());
      //
	    PM->add(llvm::createPromoteMemoryToRegisterPass());
#endif
      // tell LLVM about some built-in functions
	    EE->updateGlobalMapping("llvm_disassemble", (uint64_t)&llvm_disassemble);      
	    EE->updateGlobalMapping("llvm_destroy_zone_after_delay", (uint64_t)&llvm_destroy_zone_after_delay);
	    EE->updateGlobalMapping("free_after_delay", (uint64_t)&free_after_delay);
	    EE->updateGlobalMapping("llvm_get_next_prime", (uint64_t)&llvm_get_next_prime);
            EE->updateGlobalMapping("llvm_printf", uintptr_t(&printf));
            EE->updateGlobalMapping("llvm_fprintf", uintptr_t(&fprintf));
            EE->updateGlobalMapping("llvm_sprintf", uintptr_t(&sprintf));
            EE->updateGlobalMapping("llvm_sscanf", uintptr_t(&sscanf));
            EE->updateGlobalMapping("llvm_fscanf", uintptr_t(&fscanf));
	    EE->updateGlobalMapping("llvm_zone_create", (uint64_t)&llvm_zone_create);
	    EE->updateGlobalMapping("llvm_zone_destroy", (uint64_t)&llvm_zone_destroy);
	    EE->updateGlobalMapping("llvm_zone_print", (uint64_t)&llvm_zone_print);
	    EE->updateGlobalMapping("llvm_runtime_error", (uint64_t)&llvm_runtime_error);
	    EE->updateGlobalMapping("llvm_send_udp", (uint64_t)&llvm_send_udp);
	    EE->updateGlobalMapping("llvm_schedule_callback", (uint64_t)&llvm_schedule_callback);
	    EE->updateGlobalMapping("llvm_get_function_ptr", (uint64_t)&llvm_get_function_ptr);
            EE->updateGlobalMapping("llvm_peek_zone_stack_extern", (uint64_t)&llvm_peek_zone_stack);
	    EE->updateGlobalMapping("llvm_pop_zone_stack", (uint64_t)&llvm_pop_zone_stack);
            EE->updateGlobalMapping("llvm_push_zone_stack_extern", (uint64_t)&llvm_push_zone_stack);
	    EE->updateGlobalMapping("llvm_zone_malloc", (uint64_t)&llvm_zone_malloc);
            EE->updateGlobalMapping("llvm_zone_callback_setup", uintptr_t(&llvm_zone_callback_setup));
	    EE->updateGlobalMapping("get_address_table", (uint64_t)&get_address_table);
	    EE->updateGlobalMapping("check_address_type", (uint64_t)&check_address_type);
	    EE->updateGlobalMapping("check_address_exists", (uint64_t)&check_address_exists);
	    EE->updateGlobalMapping("get_address_offset", (uint64_t)&get_address_offset);
	    EE->updateGlobalMapping("add_address_table", (uint64_t)&add_address_table);
	    EE->updateGlobalMapping("new_address_table", (uint64_t)&new_address_table);
	    EE->updateGlobalMapping("llvm_print_pointer", (uint64_t)&llvm_print_pointer);
	    EE->updateGlobalMapping("llvm_print_i32", (uint64_t)&llvm_print_i32);
	    EE->updateGlobalMapping("llvm_print_i64", (uint64_t)&llvm_print_i64);
	    EE->updateGlobalMapping("llvm_print_f32", (uint64_t)&llvm_print_f32);
	    EE->updateGlobalMapping("llvm_print_f64", (uint64_t)&llvm_print_f64);
	    EE->updateGlobalMapping("llvm_samplerate", (uint64_t)&llvm_samplerate);
	    EE->updateGlobalMapping("llvm_frames", (uint64_t)&llvm_frames);
	    EE->updateGlobalMapping("llvm_channels", (uint64_t)&llvm_channels);
	    EE->updateGlobalMapping("llvm_in_channels", (uint64_t)&llvm_in_channels);
	    EE->updateGlobalMapping("llvm_now", (uint64_t)&llvm_now);
	    EE->updateGlobalMapping("llvm_zone_reset", (uint64_t)&llvm_zone_reset);
	    EE->updateGlobalMapping("llvm_zone_copy_ptr", (uint64_t)&llvm_zone_copy_ptr);
	    EE->updateGlobalMapping("llvm_zone_mark", (uint64_t)&llvm_zone_mark);
	    EE->updateGlobalMapping("llvm_zone_mark_size", (uint64_t)&llvm_zone_mark_size);
	    EE->updateGlobalMapping("llvm_zone_ptr_set_size", (uint64_t)&llvm_zone_ptr_set_size);
	    EE->updateGlobalMapping("llvm_zone_ptr_size", (uint64_t)&llvm_zone_ptr_size);
	    EE->updateGlobalMapping("llvm_ptr_in_zone", (uint64_t)&llvm_ptr_in_zone);
	    EE->updateGlobalMapping("llvm_ptr_in_current_zone", (uint64_t)&llvm_ptr_in_current_zone);
	    EE->updateGlobalMapping("extitoa", (uint64_t)&extitoa);
	    EE->updateGlobalMapping("string_hash", (uint64_t)&string_hash);
	    EE->updateGlobalMapping("swap64i", (uint64_t)&swap64i);
	    EE->updateGlobalMapping("swap64f", (uint64_t)&swap64f);
	    EE->updateGlobalMapping("swap32i", (uint64_t)&swap32i);
	    EE->updateGlobalMapping("swap32f", (uint64_t)&swap32f);
	    EE->updateGlobalMapping("unswap64i", (uint64_t)&unswap64i);
	    EE->updateGlobalMapping("unswap64f", (uint64_t)&unswap64f);
	    EE->updateGlobalMapping("unswap32i", (uint64_t)&unswap32i);
	    EE->updateGlobalMapping("unswap32f", (uint64_t)&unswap32f);
	    EE->updateGlobalMapping("imp_randd", (uint64_t)&imp_randd);
	    EE->updateGlobalMapping("imp_randf", (uint64_t)&imp_randf);
	    EE->updateGlobalMapping("imp_rand1_i64", (uint64_t)&imp_rand1_i64);
	    EE->updateGlobalMapping("imp_rand2_i64", (uint64_t)&imp_rand2_i64);
	    EE->updateGlobalMapping("imp_rand1_i32", (uint64_t)&imp_rand1_i32);
	    EE->updateGlobalMapping("imp_rand2_i32", (uint64_t)&imp_rand2_i32);
	    EE->updateGlobalMapping("imp_rand1_d", (uint64_t)&imp_rand1_d);
	    EE->updateGlobalMapping("imp_rand2_d", (uint64_t)&imp_rand2_d);
	    EE->updateGlobalMapping("imp_rand1_f", (uint64_t)&imp_rand1_f);
	    EE->updateGlobalMapping("imp_rand2_f", (uint64_t)&imp_rand2_f);
	    EE->updateGlobalMapping("rsplit", (uint64_t)&rsplit);
	    EE->updateGlobalMapping("rmatch", (uint64_t)&rmatch);
	    EE->updateGlobalMapping("rreplace", (uint64_t)&rreplace);
	    EE->updateGlobalMapping("base64_encode", (uint64_t)&base64_encode);
	    EE->updateGlobalMapping("base64_decode", (uint64_t)&base64_decode);
	    EE->updateGlobalMapping("cname_encode", (uint64_t)&cname_encode);
	    EE->updateGlobalMapping("cname_decode", (uint64_t)&cname_decode);
      EE->updateGlobalMapping("clock_clock", (uint64_t)&clock_clock);
      EE->updateGlobalMapping("audio_clock_base", (uint64_t)&audio_clock_base);
      EE->updateGlobalMapping("audio_clock_now", (uint64_t)&audio_clock_now);
	    EE->updateGlobalMapping("r64value", (uint64_t)&r64value);
	    EE->updateGlobalMapping("mk_double", (uint64_t)&mk_double);
	    EE->updateGlobalMapping("r32value", (uint64_t)&r32value);
	    EE->updateGlobalMapping("mk_float", (uint64_t)&mk_float);
	    EE->updateGlobalMapping("is_real", (uint64_t)&is_real);
	    EE->updateGlobalMapping("i64value", (uint64_t)&i64value);
	    EE->updateGlobalMapping("mk_i64", (uint64_t)&mk_i64);
	    EE->updateGlobalMapping("i32value", (uint64_t)&i32value);
	    EE->updateGlobalMapping("mk_i32", (uint64_t)&mk_i32);
	    EE->updateGlobalMapping("i16value", (uint64_t)&i16value);
	    EE->updateGlobalMapping("mk_i16", (uint64_t)&mk_i16);
	    EE->updateGlobalMapping("i8value", (uint64_t)&i8value);
	    EE->updateGlobalMapping("mk_i8", (uint64_t)&mk_i8);
	    EE->updateGlobalMapping("i1value", (uint64_t)&i1value);
	    EE->updateGlobalMapping("mk_i1", (uint64_t)&mk_i1);
	    EE->updateGlobalMapping("is_integer", (uint64_t)&is_integer);
	    EE->updateGlobalMapping("string_value", (uint64_t)&string_value);
	    EE->updateGlobalMapping("mk_string", (uint64_t)&mk_string);
	    EE->updateGlobalMapping("is_string", (uint64_t)&is_string);
	    EE->updateGlobalMapping("cptr_value", (uint64_t)&cptr_value);
	    EE->updateGlobalMapping("mk_cptr", (uint64_t)&mk_cptr);
	    EE->updateGlobalMapping("is_cptr", (uint64_t)&is_cptr);
	    EE->updateGlobalMapping("is_cptr_or_str", (uint64_t)&is_cptr_or_str);
	    EE->updateGlobalMapping("malloc16", (uint64_t)&malloc16);
	    EE->updateGlobalMapping("free16", (uint64_t)&free16);
	    EE->updateGlobalMapping("list_ref", (uint64_t)&list_ref);
	    EE->updateGlobalMapping("thread_fork", (uint64_t)&thread_fork);
	    EE->updateGlobalMapping("thread_join", (uint64_t)&thread_join);
	    EE->updateGlobalMapping("thread_kill", (uint64_t)&thread_kill);
	    EE->updateGlobalMapping("thread_self", (uint64_t)&thread_self);
	    EE->updateGlobalMapping("thread_equal", (uint64_t)&thread_equal);
	    EE->updateGlobalMapping("thread_equal_self", (uint64_t)&thread_equal_self);
	    EE->updateGlobalMapping("thread_sleep", (uint64_t)&thread_sleep);
	    EE->updateGlobalMapping("mutex_create", (uint64_t)&mutex_create);
	    EE->updateGlobalMapping("mutex_destroy", (uint64_t)&mutex_destroy);
	    EE->updateGlobalMapping("mutex_lock", (uint64_t)&mutex_lock);
	    EE->updateGlobalMapping("mutex_unlock", (uint64_t)&mutex_unlock);
	    EE->updateGlobalMapping("mutex_trylock", (uint64_t)&mutex_trylock);
      EE->updateGlobalMapping("llvm_tan", (uint64_t)&llvm_tan);
      EE->updateGlobalMapping("llvm_cosh", (uint64_t)&llvm_cosh);
      EE->updateGlobalMapping("llvm_tanh", (uint64_t)&llvm_tanh);
      EE->updateGlobalMapping("llvm_sinh", (uint64_t)&llvm_sinh);
      EE->updateGlobalMapping("llvm_acos", (uint64_t)&llvm_acos);
      EE->updateGlobalMapping("llvm_asin", (uint64_t)&llvm_asin);
      EE->updateGlobalMapping("llvm_atan", (uint64_t)&llvm_atan);
      EE->updateGlobalMapping("llvm_atan2", (uint64_t)&llvm_atan2);
      EE->updateGlobalMapping("sys_sharedir", (uint64_t)&sys_sharedir);
      EE->updateGlobalMapping("sys_slurp_file", (uint64_t)&sys_slurp_file);

#ifdef EXT_MCJIT
      extemp::EXTLLVM::I()->EE->finalizeObject();
#endif
      return;
    }
  }
}

extern "C" {

llvm_zone_t* llvm_peek_zone_stack_extern()
{
  return llvm_peek_zone_stack();
}

void llvm_push_zone_stack_extern (llvm_zone_t* z)
{
  llvm_push_zone_stack(z);
}


}
