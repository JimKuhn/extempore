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

#ifndef UNIV_H
#define UNIV_H

#include <stdint.h>
#include <BranchPrediction.h>

#ifdef EXT_BOOST
#include <random>
#endif

#include <string>
#include <vector>
#include <map>

#ifdef _WIN32
#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN
#endif

#if _WIN32 || _WIN64
#if _WIN64
#define TARGET_64BIT
#else
#define TARGET_32BIT
#endif
#endif

#if __GNUC__
#if __x86_64__ || __ppc64__
#define TARGET_64BIT
#else
#define TARGET_32BIT
#endif
#endif

#define BILLION  1000000000L
#define D_BILLION 1000000000.0
#define D_MILLION 1000000.0


#ifdef _WIN32
#define OS_PATH_DELIM '\\'
#else
#define OS_PATH_DELIM '/'
#endif

/*
struct regex_matched_buffer
{
  int matches;
  char* data[100];
  };
*/

struct scheme;
struct cell;
typedef struct cell* pointer;

extern "C" {

bool rmatch(char* regex, char* str);
int64_t rmatches(char* regex, char* str, char** results,int64_t maxnum); //struct regex_matched_buffer* result);
bool rsplit(char* regex, char* str, char* a, char* b);
char* rreplace(char* regex, char* str, char* replacement, char* result);
char* base64_encode(const unsigned char *data,size_t input_length,size_t *output_length);
unsigned char* base64_decode(const char *data,size_t input_length,size_t *output_length);
char* cname_encode(char *data,size_t input_length,size_t *output_length);
char* cname_decode(char *data,size_t input_length,size_t *output_length);
const char* sys_sharedir();
char* sys_slurp_file(const char* fname);
int register_for_window_events();

}

namespace extemp {

//#define mk_cb(instance,class,func) (dynamic_cast<CM*>(new CMI<class>(instance,&class::func)))
    
  class UNIV {

#define EIGHT_BIT 127
#define SIXTEEN_BIT 32767
#define TWENTY_FOUR_BIT 8388608
#define THIRTY_TWO_BIT 214748647
    
  public:
    static std::string SHARE_DIR;
    static uint32_t CHANNELS;
    static uint32_t IN_CHANNELS;
    static uint32_t SAMPLERATE;
    static volatile uint64_t TIME;
    static uint64_t DEVICE_TIME;
    static double AUDIO_CLOCK_BASE;
    static double AUDIO_CLOCK_NOW;
    static uint64_t TIME_DIVISION;
    static uint32_t SECOND() { return SAMPLERATE; }
    static uint32_t MINUTE() { return SAMPLERATE * 60; }
    static uint32_t HOUR() { return MINUTE() * 60; }
    static uint32_t FRAMES;
    static uint32_t EXT_TERM;
    static bool EXT_LOADBASE;
    static uint32_t AUDIO_NONE;
    static uint32_t AUDIO_DEVICE;
    static uint32_t AUDIO_IN_DEVICE;
    static double CLOCK_OFFSET;
    static std::map<std::string,std::string> CMDPARAMS;
    static std::string ARCH;
    static std::string CPU;
    static std::vector<std::string> ATTRS;
#ifdef EXT_BOOST
    static std::random_device RNGDEV;
    static std::mt19937_64 RNGGEN;
    static std::uniform_real_distribution<double> uniform_01;
#endif

    static double midi2frq(double pitch);
    static double frqRatio(double semitones);
    static void initRand();
    static int random(int range);
    static double random();
    static bool file_check(const std::string& filename);
    static void printSchemeCell(scheme* sc, std::stringstream& ss, pointer cell, bool = false, bool = true);
     
  private:

  };

extern "C" {
//////////////////////////////////////////////////////////////////
//  CLOCK/TIME
#ifdef EXT_BOOST
#include <chrono>

inline double getRealTime()
{
    return std::chrono::high_resolution_clock::now().time_since_epoch().count();
}

#elif __linux__

inline double getRealTime()
{
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec + t.tv_nsec / D_BILLION;
}

#elif __APPLE__

#include <CoreAudio/HostTime.h>

inline double getRealTime()
{
    return CFAbsoluteTimeGetCurrent() + kCFAbsoluteTimeIntervalSince1970;
}

#endif

inline double clock_clock()
{
    return getRealTime() + extemp::UNIV::CLOCK_OFFSET;
}

inline double audio_clock_base()
{
    return extemp::UNIV::AUDIO_CLOCK_BASE;
}

inline double audio_clock_now()
{
    return extemp::UNIV::AUDIO_CLOCK_NOW;
}
}

} //End Namespace

inline void ascii_text_color(bool Bold, unsigned Foreground, unsigned Background)
{
    if (unlikely(extemp::UNIV::EXT_TERM == 3)) {
        return;
    }
#ifdef _WIN32
    extern int WINDOWS_COLORS;
    if (unlikely(extemp::UNIV::EXT_TERM == 1)) {
        Foreground = std::min(Foreground, 7);
        HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(console, WINDOWS_COLORS[Foreground]);
        return;
    }
#else
    // if simple term (that doesn't support defaults)
    // then default to black background and white text
    Foreground = (Foreground > 9 || Foreground == 8) ? 9 : Foreground;
    Background = (Background > 9 || Background == 8) ? 9 : Background;
    if (unlikely(extemp::UNIV::EXT_TERM == 2)) {
        if (unlikely(Background == 9)) {
            Background = 0;
        }
        if (unlikely(Foreground == 9)) {
            Foreground = 7;
        }
    }
    printf("\x1b[%u;%u;%um", Bold, Foreground + 30, Background + 40);
#endif
}

inline void ascii_default() { ascii_text_color(false, 9, 9); }
inline void ascii_normal() { ascii_text_color(false, 7, 9); }
inline void ascii_error() { ascii_text_color(true, 1, 9); }
inline void ascii_warning() { ascii_text_color(true, 3, 9); }
inline void ascii_info() { ascii_text_color(true, 6, 9); }

#endif
