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

#include <fstream>

// must be included before anything which pulls in <Windows.h>
#include "llvm/ADT/StringExtras.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm-c/Core.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/ExecutionEngine/Interpreter.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/LinkAllPasses.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MutexGuard.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/raw_os_ostream.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Verifier.h"

#include "SchemeFFI.h"
#include "AudioDevice.h"
#include "UNIV.h"
#include "TaskScheduler.h"
#include "SchemeProcess.h"
#include "SchemeREPL.h"
#include <unordered_set>
#include <unordered_map>

#ifdef _WIN32
#include <Windows.h>
#include <Windowsx.h>
#include <filesystem>
#include <fstream>
#else
#include <dlfcn.h>
#include <dirent.h>
#endif

// setting this define should make call_compiled thread safe BUT ...
// also extremely SLOW !

#define LLVM_EE_LOCK

#include <regex>

////////////////////////////////

#include "pcre.h"

#ifdef __APPLE__
#include <malloc/malloc.h>
#else
#include <time.h>
#endif

#ifdef _WIN32
//#include <unistd.h>
#include <malloc.h>
#elif __APPLE__
#include <Cocoa/Cocoa.h>
#include <CoreFoundation/CoreFoundation.h>
#include <AppKit/AppKit.h>
#endif

#ifdef _WIN32
#define PRINT_ERROR(format, ...)                \
    ascii_error();                   \
    printf(format , __VA_ARGS__);                       \
    ascii_normal()
#else
#define PRINT_ERROR(format, args...)            \
    ascii_error();                   \
    printf(format , ## args);                   \
    ascii_normal()
#endif

#include <queue>
#include <unistd.h>
#include <EXTMutex.h>
namespace extemp { namespace SchemeFFI {
static llvm::Module* jitCompile(const std::string& String);
}}

static inline std::string xtm_ftostr(double V) {
  char Buffer[200];
  sprintf(Buffer, "%20.6e", V);
  char *B = Buffer;
  while (*B == ' ') ++B;
  return B;
}

static inline std::string xtm_ftostr(const llvm::APFloat& V) {
  if (&V.getSemantics() == &llvm::APFloat::IEEEdouble)
    return xtm_ftostr(V.convertToDouble());
  else if (&V.getSemantics() == &llvm::APFloat::IEEEsingle)
    return xtm_ftostr((double)V.convertToFloat());
  return "<unknown format in ftostr>"; // error
}

namespace extemp {

namespace SchemeFFI {

static std::unordered_map<std::string,std::pair<std::string,std::string>> IMPCIR_DICT;
static char* tmp_str_a = reinterpret_cast<char*>(malloc(1024));
static char* tmp_str_b = (char*) malloc(4096);
static std::unordered_map<std::string,std::string> LLVM_ALIAS_TABLE;

#include "ffi/utility.inc"
#include "ffi/ipc.inc"
#include "ffi/assoc.inc"
#include "ffi/number.inc"
#include "ffi/sys.inc"
#include "ffi/sys_dsp.inc"
#include "ffi/sys_zone.inc"
#include "ffi/misc.inc"
#include "ffi/regex.inc"

void initSchemeFFI(scheme* sc)
{
    static struct {
        const char* name;
        uint32_t    value;
    } integerTable[] = {
        { "*au:block-size*", UNIV::FRAMES },
        { "*au:samplerate*", UNIV::SAMPLERATE },
        { "*au:channels*", UNIV::CHANNELS },
        { "*au:in-channels*", UNIV::IN_CHANNELS },
    };
    for (auto& elem: integerTable) {
        scheme_define(sc, sc->global_env, mk_symbol(sc, elem.name), mk_integer(sc, elem.value));
    }
    static struct {
        const char*  name;
        foreign_func func;
    } funcTable[] = {
        UTILITY_DEFS,
        IPC_DEFS,
        ASSOC_DEFS,
        NUMBER_DEFS,
        SYS_DEFS,
        SYS_DSP_DEFS,
        SYS_ZONE_DEFS,
        MISC_DEFS,
        REGEX_DEFS,
        // llvm stuff
        {     "llvm:optimize",                  &optimizeCompiles             },
        {     "llvm:fast-compile",              &fastCompiles                 },
        {     "llvm:jit-compile-ir-string",     &jitCompileIRString},
        {     "llvm:ffi-set-name",              &ff_set_name                  },
        {     "llvm:ffi-get-name",              &ff_get_name                  },
        {     "llvm:get-function",              &get_function                 },
        {     "llvm:get-globalvar",             &get_globalvar                },
        {     "llvm:get-struct-size",           &get_struct_size              },
        {     "llvm:get-named-struct-size",     &get_named_struct_size        },
        {     "llvm:get-function-args",         &get_function_args            },
        {     "llvm:get-function-varargs",      &get_function_varargs         },
        {     "llvm:get-function-type",         &get_function_type            },
        {     "llvm:get-function-calling-conv", &get_function_calling_conv    },
        {     "llvm:get-global-variable-type",  &get_global_variable_type     },
        {     "llvm:get-function-pointer",      &get_function_pointer         },
        {     "llvm:remove-function",           &remove_function              },
        {     "llvm:remove-globalvar",          &remove_global_var            },
        {     "llvm:erase-function",            &erase_function               },
        {     "llvm:call-void-func",            &llvm_call_void_native        },
        {     "llvm:run",                       &call_compiled                },
        {     "llvm:convert-float",             &llvm_convert_float_constant  },
        {     "llvm:convert-double",            &llvm_convert_double_constant },
        {     "llvm:count",                     &llvm_count                   },
        {     "llvm:count-set",                 &llvm_count_set               },
        {     "llvm:count++",                   &llvm_count_inc               },
        {     "llvm:call-closure",              &callClosure                  },
        {     "llvm:print",                     &printLLVMModule              },
        {     "llvm:print-function",            &printLLVMFunction            },
        {     "llvm:print-all-closures",        &llvm_print_all_closures      },
        {     "llvm:print-closure",             &llvm_print_closure           },
        {     "llvm:get-closure-work-name",     &llvm_closure_last_name       },
        {     "llvm:disassemble",               &llvm_disasm                  },
        {     "llvm:bind-symbol",               &bind_symbol                  },
        {     "llvm:update-mapping",            &update_mapping               },
        {     "llvm:add-llvm-alias",            &add_llvm_alias               },
        {     "llvm:get-llvm-alias",            &get_llvm_alias               },
        {     "llvm:get-named-type",            &get_named_type               },
        {     "llvm:get-global-module",         &get_global_module            },
        {     "llvm:export-module",             &export_llvmmodule_bitcode    },
        {     "impc:ir:getname",                &impcirGetName                },
        {     "impc:ir:gettype",                &impcirGetType                },
        {     "impc:ir:addtodict",              &impcirAdd                    },
        {     "clock:set-offset",               &setClockOffset               },
        {     "clock:get-offset",               &getClockOffset               },
        {     "clock:adjust-offset",            &adjustClockOffset            },
        {     "clock:clock",                    &getClockTime                 },
        {     "clock:ad:clock",                 &lastSampleBlockClock         },
    };
    for (auto& elem : funcTable) {
        scheme_define(sc, sc->global_env, mk_symbol(sc, elem.name), mk_foreign_func(sc, elem.func));
    }
}

    //////////////////// helper functions ////////////////////////
    void addGlobal(scheme* sc, char* symbol_name, pointer arg)
    {
        scheme_define(sc, sc->global_env, mk_symbol(sc, symbol_name), arg);
    }

    // pointer scmAddForeignFunc(scheme* sc, pointer Args) {
    //   //char* sym_name = string_value(pair_car(Args));
    //   foreign_func func = (foreign_func) cptr_value(pair_car(Args));
    //   //scheme_define(sc, sc->global_env, mk_symbol(sc, symbol_name), mk_foreign_func(sc, func));
    //   return mk_foreign_func(sc,func); //sc->T;
    // }
void addForeignFunc(scheme* sc, char* symbol_name, foreign_func func)
{
    scheme_define(sc, sc->global_env, mk_symbol(sc, symbol_name), mk_foreign_func(sc, func));
}



    void addGlobalCptr(scheme* sc, char* symbol_name, void* ptr)
    {
        scheme_define(sc, sc->global_env, mk_symbol(sc, symbol_name), mk_cptr(sc, ptr));
    }

    pointer impcirGetType(scheme* Scheme, pointer Args)
    {
                std::string key(string_value(pair_car(Args)));
                return mk_string(Scheme, IMPCIR_DICT[key].second.c_str());
    }

    pointer impcirGetName(scheme* Scheme, pointer Args)
    {
                std::string key(string_value(pair_car(Args)));
                return mk_string(Scheme, IMPCIR_DICT[key].first.c_str());
    }

    pointer impcirAdd(scheme* Scheme, pointer Args)
    {
                std::string current("current");
                std::string previous("previous");
                std::string key(string_value(pair_car(Args)));
                std::string name(string_value(pair_cadr(Args)));
                std::string type(string_value(pair_caddr(Args)));
                //std::cout << "ADDING IN C++ "  << key << " " << name << " " << type << std::endl;
                std::pair<std::string,std::string> p(name,type);
                IMPCIR_DICT[previous] = IMPCIR_DICT[current];
                IMPCIR_DICT[current] = p;
                IMPCIR_DICT[key] = p;
                return Scheme->T;
    }

    ///////////////////////////////////////////////////////
    //
    // REGEX STUFF
    //
    //////////////////////////////////////////////////////


    void freeWithDelay(TaskI* task)
    {
        Task<char*>* t = static_cast<Task<char*>*>(task);
        char* dat = t->getArg();
        free(dat);
    }

    void destroyMallocZoneWithDelay(TaskI* task)
    {
        Task<llvm_zone_t*>* t = static_cast<Task<llvm_zone_t*>*>(task);
        llvm_zone_t* zone = t->getArg();
        llvm_zone_destroy(zone);
    }





    ////////////////////////////////////////////
    //
    // LLVM STUFF
    //
    /////////////////////////////////////////////

pointer optimizeCompiles(scheme* Scheme, pointer Args)
{
    EXTLLVM::OPTIMIZE_COMPILES = (pair_car(Args) == Scheme->T);
    return Scheme->T;
}

pointer fastCompiles(scheme* Scheme, pointer Args)
{
    EXTLLVM::FAST_COMPILES = (pair_car(Args) == Scheme->T);
    return Scheme->T;
}

pointer verifyCompiles(scheme* Scheme, pointer Args)
{
    EXTLLVM::VERIFY_COMPILES = (pair_car(Args) == Scheme->T);
    return Scheme->T;
}

  static long long llvm_emitcounter = 0;

static std::string SanitizeType(llvm::Type* Type)
{
    std::string type;
    llvm::raw_string_ostream typeStream(type);
    Type->print(typeStream);
    auto str(typeStream.str());
    std::string::size_type pos(str.find('='));
    if (pos != std::string::npos) {
        str.erase(pos - 1);
    }
    return str;
}

static bool sEmitCode = false;
static std::regex sGlobalSymRegex("@([-a-zA-Z$._][-a-zA-Z$._0-9]*)", std::regex::optimize);
static std::regex sDefineSymRegex("define[^\\n]+@([-a-zA-Z$._][-a-zA-Z$._0-9]*)", std::regex::optimize | std::regex::ECMAScript);

static llvm::Module* jitCompile(const std::string& String)
{
    // Create some module to put our function into it.
    using namespace llvm;
    legacy::PassManager* PM = extemp::EXTLLVM::I()->PM;
    legacy::PassManager* PM_NO = extemp::EXTLLVM::I()->PM_NO;

    char modname[256];
    sprintf(modname, "xtmmodule_%lld", ++llvm_emitcounter);
    char tmpbuf[1024];

    std::string asmcode(String);
    SMDiagnostic pa;

    static std::string sInlineString; // This is a hack for now, but it *WORKS*
    static std::string sInlineBitcode;
    static std::unordered_set<std::string> sInlineSyms;
    if (sInlineString.empty()) {
        {
            std::ifstream inStream(UNIV::SHARE_DIR + "/runtime/bitcode.ll");
            std::stringstream inString;
            inString << inStream.rdbuf();
            sInlineString = inString.str();
        }
        std::copy(std::sregex_token_iterator(sInlineString.begin(), sInlineString.end(), sGlobalSymRegex, 1),
                std::sregex_token_iterator(), std::inserter(sInlineSyms, sInlineSyms.begin()));
        {
            std::ifstream inStream(UNIV::SHARE_DIR + "/runtime/inline.ll");
            std::stringstream inString;
            inString << inStream.rdbuf();
            std::string tString = inString.str();
            std::copy(std::sregex_token_iterator(tString.begin(), tString.end(), sGlobalSymRegex, 1),
                    std::sregex_token_iterator(), std::inserter(sInlineSyms, sInlineSyms.begin()));
        }
    }
    if (sInlineBitcode.empty()) {
        // need to avoid parsing the types twice
        static bool first(true);
        if (!first) {
            auto newModule(parseAssemblyString(sInlineString, pa, getGlobalContext()));
            if (newModule) {
                std::string bitcode;
                llvm::raw_string_ostream bitstream(sInlineBitcode);
                llvm::WriteBitcodeToFile(newModule.get(), bitstream);
                std::ifstream inStream(UNIV::SHARE_DIR + "/runtime/inline.ll");
                std::stringstream inString;
                inString << inStream.rdbuf();
                sInlineString = inString.str();
            } else {
std::cout << pa.getMessage().str() << std::endl;
                abort();
            }
        } else {
            first = false;
        }
    }
    std::unique_ptr<llvm::Module> newModule;
    bool built(false);
    if (!EXTLLVM::FAST_COMPILES) { // this might not be necessary any more (benchmark later)
        auto context(LLVMContextCreate());
        newModule = parseAssemblyString(asmcode, pa, *unwrap(context));
        built = bool(newModule);
        newModule.reset();
        LLVMContextDispose(context);
    }
    if (likely(!built)) {
        std::vector<std::string> symbols;
        std::copy(std::sregex_token_iterator(asmcode.begin(), asmcode.end(), sGlobalSymRegex, 1),
                std::sregex_token_iterator(), std::inserter(symbols, symbols.begin()));
        std::sort(symbols.begin(), symbols.end());
        auto end(std::unique(symbols.begin(), symbols.end()));
        std::unordered_set<std::string> ignoreSyms;
        std::copy(std::sregex_token_iterator(asmcode.begin(), asmcode.end(), sDefineSymRegex, 1),
                std::sregex_token_iterator(), std::inserter(ignoreSyms, ignoreSyms.begin()));
        std::string declarations;
        llvm::raw_string_ostream dstream(declarations);
        for (auto iter = symbols.begin(); iter != end; ++iter) {
            const char* sym(iter->c_str());
            if ((!EXTLLVM::FAST_COMPILES && sInlineSyms.find(sym) != sInlineSyms.end()) ||
                    ignoreSyms.find(sym) != ignoreSyms.end()) {
                continue;
            }
            auto gv = extemp::EXTLLVM::I()->getGlobalValue(sym);
            if (!gv) {
                continue;
            }
            auto func(extemp::EXTLLVM::I()->getFunction(sym));
            if (func) {
                dstream << "declare " << SanitizeType(func->getReturnType()) << " @" << sym << " (";
                bool first(true);
                for (const auto& arg : func->getArgumentList()) {
                    if (!first) {
                        dstream << ", ";
                    } else {
                        first = false;
                    }
                    dstream << SanitizeType(arg.getType());
                }
                if (func->isVarArg()) {
                    dstream << ", ...";
                }
                dstream << ")\n";
            } else {
                auto str(SanitizeType(gv->getType()));
                dstream << '@' << sym << " = external global " << str.substr(0, str.length() - 1) << '\n';
            }
        }
// std::cout << "**** DECL ****\n" << dstream.str() << "**** ENDDECL ****\n" << std::endl;
        if (!EXTLLVM::FAST_COMPILES) {
            auto modOrErr(parseBitcodeFile(llvm::MemoryBufferRef(sInlineBitcode, "<string>"), getGlobalContext()));
            if (likely(modOrErr)) {
                newModule = std::move(modOrErr.get());
                asmcode = sInlineString + dstream.str() + asmcode;
if (sEmitCode) {
    std::cout << "EMITTING\n" << asmcode << "DONE EMITTING\n";
}
                if (parseAssemblyInto(llvm::MemoryBufferRef(asmcode, "<string>"), *newModule, pa)) {
std::cout << "**** DECL ****\n" << dstream.str() << "**** ENDDECL ****\n" << std::endl;
                    newModule.reset();
                }
            }
        } else {
            newModule = parseAssemblyString(dstream.str() + asmcode, pa, getGlobalContext());
        }
    } else {
        newModule = parseAssemblyString(asmcode, pa, getGlobalContext());
    }
    if (newModule) {
        if (unlikely(!extemp::UNIV::ARCH.empty())) {
            newModule->setTargetTriple(extemp::UNIV::ARCH);
        }
        if (!EXTLLVM::FAST_COMPILES) {
            if (EXTLLVM::OPTIMIZE_COMPILES) {
                PM->run(*newModule);
            } else {
                PM_NO->run(*newModule);
            }
        }
    }
    //std::stringstream ss;
    if (unlikely(!newModule))
    {
// std::cout << "**** CODE ****\n" << asmcode << " **** ENDCODE ****" << std::endl;
// std::cout << pa.getMessage().str() << std::endl << pa.getLineNo() << std::endl;
        std::string errstr;
        llvm::raw_string_ostream ss(errstr);
        pa.print("LLVM IR",ss);
        printf("%s\n",ss.str().c_str());
        return nullptr;
    } else if (extemp::EXTLLVM::VERIFY_COMPILES && verifyModule(*newModule)) {
        std::cout << "\nInvalid LLVM IR\n";
        return nullptr;
    }
    llvm::Module *modulePtr = newModule.get();
    extemp::EXTLLVM::I()->EE->addModule(std::move(newModule));
    extemp::EXTLLVM::I()->EE->finalizeObject();
    return modulePtr;
}

pointer jitCompileIRString(scheme* Scheme, pointer Args)
{
    auto modulePtr(jitCompile(string_value(pair_car(Args))));
    if (!modulePtr) {
        return Scheme->F;
    }
    extemp::EXTLLVM::I()->addModule(modulePtr);
    return mk_cptr(Scheme, modulePtr);
}


    pointer ff_set_name(scheme* Scheme, pointer Args)
    {
       pointer x = pair_car(Args);
       foreign_func ff = x->_object._ff;
       char* name = string_value(pair_cadr(Args));
       llvm_scheme_ff_set_name(ff,name);
       return Scheme->T;
    }

    pointer ff_get_name(scheme* Scheme, pointer Args)
    {
       pointer x = pair_car(Args);
       foreign_func ff = x->_object._ff;
       const char* name = llvm_scheme_ff_get_name(ff);
       return mk_string(Scheme,name);
    }

  pointer get_function(scheme* Scheme, pointer Args)
  {
    using namespace llvm;
    llvm::Function* func = extemp::EXTLLVM::I()->getFunction(string_value(pair_car(Args)));
    if(func == 0)
      {
        return Scheme->F;
      }
    return mk_cptr(Scheme, func);
  }

  pointer get_globalvar(scheme* Scheme, pointer Args)
  {
    using namespace llvm;

    llvm::GlobalVariable* var = extemp::EXTLLVM::I()->getGlobalVariable(string_value(pair_car(Args)));
    if(var == 0)
      {
        return Scheme->F;
      }
    return mk_cptr(Scheme, var);
  }


  pointer get_function_calling_conv(scheme* Scheme, pointer Args)
  {
    llvm::Function* func = extemp::EXTLLVM::I()->getFunction(string_value(pair_car(Args)));
    if(func == 0)
      {
        return Scheme->F;
      }

    int cc = func->getCallingConv();
    return mk_integer(Scheme, cc);
  }

  pointer get_function_varargs(scheme* Scheme, pointer Args)
  {
    using namespace llvm;
    llvm::Function* func = extemp::EXTLLVM::I()->getFunction(string_value(pair_car(Args)));
    if(func == 0)
      {
        return Scheme->F;
      }
    return func->isVarArg() ? Scheme->T : Scheme->F;
  }

  pointer llvm_print_all_closures(scheme* Scheme, pointer Args)
  {
    using namespace llvm;
    char* x = string_value(pair_car(Args));
    char rgx[1024];
    strcpy(rgx, x);
    strcat(rgx, "_.*");
    // printf("check regex: %s\n",(char*)&rgx[0]);

    Module* M = NULL;
    std::vector<llvm::Module*> Ms = EXTLLVM::I()->getModules();
    for (int i=0;i<Ms.size();i++) {
      M = Ms[i];
      for (Module::const_iterator GI = M->begin(), GE = M->end(); GI != GE; ++GI) {
        const llvm::Function* func = &*GI;
        if (func->hasName() && rmatch((char*)&rgx[0],(char*)func->getName().data())) {
          //printf("HIT %s\n",func->getName().data());
          std::string str;
          llvm::raw_string_ostream ss(str);
          ss << *func;
          printf("\n---------------------------------------------------\n%s",str.c_str());
        }
      }
    }
    return Scheme->T;
  }

  pointer llvm_closure_last_name(scheme* Scheme, pointer Args)
  {
    using namespace llvm;
    char* x = string_value(pair_car(Args));
    char rgx[1024];
    strcpy(rgx, x);
    strcat(rgx, "__[0-9]*");
    // printf("check regex: %s\n",(char*)&rgx[0]);
    char* last_name = NULL;

    Module* M = NULL;
    std::vector<llvm::Module*> Ms = EXTLLVM::I()->getModules();
    for (int i=0;i<Ms.size();i++) {
      M = Ms[i];
      for (Module::const_iterator GI = M->begin(), GE = M->end(); GI != GE; ++GI) {
        const llvm::Function* func = &*GI;
        if (func->hasName() && rmatch((char*)&rgx[0],(char*)func->getName().data())) {
          last_name = (char*)func->getName().data();
        }
      }
    }
    //std::cout << "fullname:" << last_name << std::endl;
    if(last_name) return mk_string(Scheme,last_name);
    else return Scheme->F;
  }


    pointer llvm_print_closure(scheme* Scheme, pointer Args)
  {
    using namespace llvm;
    char* fname = string_value(pair_car(Args));

    Module* M = NULL;
    std::vector<llvm::Module*> Ms = EXTLLVM::I()->getModules();
    for (int i=0;i<Ms.size();i++) {
      M = Ms[i];
      for (Module::const_iterator GI = M->begin(), GE = M->end(); GI != GE; ++GI) {
        const llvm::Function* func = &*GI;
        if (func->hasName() && strcmp(func->getName().data(),fname)==0) {
          std::string str;
          llvm::raw_string_ostream ss(str);
          ss << *func;
          if(str.find_first_of("{") != std::string::npos) {
            std::cout << str << std::endl;
          }
          //printf("\n---------------------------------------------------\n%s",str.c_str());
        }
      }
    }
    return Scheme->T;
  }


  pointer llvm_disasm(scheme* Scheme, pointer Args)
  {
    //using namespace llvm;
    //long bytes = ivalue(pair_cadr(Args));
    //int x64 = (pair_caddr(Args) == Scheme->T) ? 1 : 0;
    int lgth = list_length(Scheme, Args);
    int syntax = 1;
    if(lgth > 1) {
      syntax = ivalue(pair_cadr(Args));
    }
    if (syntax > 1) {
      std::cout << "Syntax argument must be either 0: at&t or 1: intel" << std::endl;
      std::cout << "The default is 1: intel" << std::endl;
      syntax = 1;
    }
    pointer name = llvm_closure_last_name(Scheme, Args);
    unsigned char* fptr = (unsigned char*) cptr_value(get_function_pointer(Scheme,cons(Scheme,name,pair_cdr(Args))));
    char* dasm = llvm_disassemble(fptr,syntax); //,bytes,x64);
    return mk_string(Scheme,dasm);
  }

  pointer get_struct_size(scheme* Scheme, pointer Args)
  {
    using namespace llvm;

    legacy::PassManager* PM = extemp::EXTLLVM::I()->PM;

    char* struct_type_str = string_value(pair_car(Args));
    unsigned long long hash = string_hash((unsigned char*)struct_type_str);
    char name[128];
    sprintf(name,"_xtmT%lld",hash);
    char assm[1024];
    sprintf(assm,"%%%s = type %s",name,struct_type_str);
    //printf("parse this! %s\n",assm);
    SMDiagnostic pa;
    // Don't!! write this into the default module!

    std::unique_ptr<llvm::Module> newM = parseAssemblyString(assm, pa, getGlobalContext());

    if(newM == 0)
      {
        return Scheme->F;
      }
    StructType* type = newM->getTypeByName(name);
    if(type == 0)
      {
        return Scheme->F;
      }
    DataLayout* layout = new DataLayout(newM.get());
    const StructLayout* sl = layout->getStructLayout(type);
    long size = sl->getSizeInBytes();
    delete layout;
    return mk_integer(Scheme,size);
  }

  pointer get_named_struct_size(scheme* Scheme, pointer Args)
  {
    using namespace llvm;

    Module* M = EXTLLVM::I()->M;
    //StructType* type = M->getTypeByName(std::string(string_value(pair_car(Args))));
    StructType* type = extemp::EXTLLVM::I()->getNamedType(string_value(pair_car(Args)));
    if(type == 0)
      {
        return Scheme->F;
      }
    DataLayout* layout = new DataLayout(M);
    const StructLayout* sl = layout->getStructLayout(type);
    long size = sl->getSizeInBytes();
    delete layout;
    return mk_integer(Scheme,size);
  }

  pointer get_function_type(scheme* Scheme, pointer Args)
  {
    using namespace llvm;
    llvm::Function* func = extemp::EXTLLVM::I()->getFunction(string_value(pair_car(Args)));
    if(func == 0)
      {
        return Scheme->F;
      }

    std::string typestr;
    llvm::raw_string_ostream ss(typestr);
    func->getFunctionType()->print(ss);
    //printf("%s\n",ss.str().c_str());
    pointer str = mk_string(Scheme, ss.str().c_str()); //func->getFunctionType()->getDescription().c_str());
    return str;
  }


  pointer get_global_module(scheme* Scheme, pointer Args)
  {
    using namespace llvm;

    Module* M = EXTLLVM::I()->M;
    if(M == NULL)
      {
        return Scheme->F;
      }
    return mk_cptr(Scheme, M);
  }


  pointer export_llvmmodule_bitcode(scheme* Scheme, pointer Args)
  {
    using namespace llvm;

    Module* m = (Module *)cptr_value(pair_car(Args));

    if(m == 0)
      {
        return Scheme->F;
      }

    char* filename = string_value(pair_cadr(Args));
#ifdef _WIN32
    std::string str;
    std::ofstream fout(filename);
    llvm::raw_string_ostream ss(str);
    ss << *m;
    std::string irStr = ss.str();

    // add dllimport (otherwise global variables won't work)
    std::string oldStr(" external global ");
    std::string newStr(" external dllimport global ");
    size_t pos = 0;

    while((pos = irStr.find(oldStr, pos)) != std::string::npos)
      {
        irStr.replace(pos, oldStr.length(), newStr);
        pos += newStr.length();
      }

    // LLVM can't handle guaranteed tail call under win64 yet
    oldStr = std::string(" tail call ");
    newStr = std::string(" call ");
    pos = 0;

    while((pos = irStr.find(oldStr, pos)) != std::string::npos)
      {
        irStr.replace(pos, oldStr.length(), newStr);
        pos += newStr.length();
      }

    fout << irStr; //ss.str();
    fout.close();
#else
    std::error_code errcode;
    llvm::raw_fd_ostream ss(filename, errcode, llvm::sys::fs::F_RW);
    if(errcode) {
      std::cout << errcode.message() << std::endl;
      return Scheme->F;
    }
    llvm::WriteBitcodeToFile(m,ss);
#endif
    return Scheme->T;
  }

  pointer get_function_args(scheme* Scheme, pointer Args)
  {
    llvm::Function* func = extemp::EXTLLVM::I()->getFunction(string_value(pair_car(Args)));
    if(func == 0)
      {
        return Scheme->F;
      }

    std::string typestr;
    llvm::raw_string_ostream ss(typestr);
    func->getReturnType()->print(ss);

    const char* tmp_name = ss.str().c_str();
    const char* eq_type_string = " = type ";

    if(func->getReturnType()->isStructTy()) {
      rsplit((char*)eq_type_string,(char*)tmp_name,tmp_str_a,tmp_str_b);
      tmp_name = tmp_str_a;
    }

    pointer str = mk_string(Scheme, tmp_name); //Scheme, ss.str().c_str()); //func->getReturnType()->getDescription().c_str());
    pointer p = cons(Scheme, str, Scheme->NIL);

    llvm::Function::ArgumentListType::iterator funcargs = func->getArgumentList().begin();
    while(funcargs != func->getArgumentList().end())
      {
        llvm::Argument* a = &*funcargs;
        {
            EnvInjector injector(Scheme, p);
        std::string typestr2;
        llvm::raw_string_ostream ss2(typestr2);
        a->getType()->print(ss2);

        tmp_name = ss2.str().c_str();

        if(a->getType()->isStructTy()) {
          rsplit((char*)eq_type_string,(char*)tmp_name,tmp_str_a,tmp_str_b);
          //printf("tmp:%s  a:%s  b:%s\n",(char*)tmp_name,tmp_str_a,tmp_str_b);
          tmp_name = tmp_str_a;
        }

        pointer str = mk_string(Scheme, tmp_name); //Scheme, ss2.str().c_str()); //a->getType()->getDescription().c_str());
        }
        p = cons(Scheme, str, p);
        funcargs++;
      }
    return reverse(Scheme, p);
  }

pointer remove_global_var(scheme* Scheme, pointer Args)
{
    auto var(EXTLLVM::I()->EE->FindGlobalVariableNamed(string_value(pair_car(Args))));
    if (!var)
    {
        return Scheme->F;
    }
    var->dropAllReferences();
    var->removeFromParent();
    return Scheme->T;
}

pointer remove_function(scheme* Scheme, pointer Args)
{
    auto func(EXTLLVM::I()->EE->FindFunctionNamed(string_value(pair_car(Args))));
    if (!func)
    {
        return Scheme->F;
    }
    if (func->mayBeOverridden()) {
        func->dropAllReferences();
        func->removeFromParent();
        return Scheme->T;
    } else {
        printf("Cannot remove function with dependencies\n");
        return Scheme->F;
    }
}

pointer erase_function(scheme* Scheme, pointer Args)
{
    auto func(EXTLLVM::I()->EE->FindFunctionNamed(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    func->deleteBody();
    func->eraseFromParent();
    return Scheme->T;
}

    pointer callClosure(scheme* Scheme, pointer Args)
    {
        using namespace llvm;
        uint32_t** closure = (uint32_t**) cptr_value(pair_car(Args));
        void* eptr = (void*) *(closure+0);
        int64_t (*fptr)(void*, int64_t) = (int64_t (*)(void*, int64_t)) *(closure+1);
        return mk_integer(Scheme, (*fptr)(eptr,ivalue(pair_cadr(Args))));
    }

  pointer get_global_variable_type(scheme* Scheme, pointer Args)
  {
    using namespace llvm;

    //Module* M = EXTLLVM::I()->M;
    //Module::global_iterator i = M->global_begin();
    //GlobalVariable* var = M->getNamedGlobal(std::string(string_value(pair_car(Args))));
    llvm::GlobalVariable* var = extemp::EXTLLVM::I()->getGlobalVariable(string_value(pair_car(Args)));
    if(var == 0)
      {
        return Scheme->F;
      }
    std::string typestr;
    llvm::raw_string_ostream ss(typestr);
    var->getType()->print(ss);
    return mk_string(Scheme, ss.str().c_str()); //var->getType()->getDescription().c_str());
  }

  pointer get_function_pointer(scheme* Scheme, pointer Args)
  {
    auto name(string_value(pair_car(Args)));
    // llvm::Function* func = EXTLLVM::I()->getFunction(string_value(pair_car(Args)));
    void* p = EXTLLVM::I()->EE->getPointerToGlobalIfAvailable(name);
    if (!p) { // look for it as a JIT-compiled function
        p = reinterpret_cast<void*>(EXTLLVM::I()->EE->getFunctionAddress(name));
        if (!p) {
            return Scheme->F;
        }
    }
    return mk_cptr(Scheme, p);
  }

  pointer llvm_call_void_native(scheme* Scheme, pointer Args)
  {
    using namespace llvm;

    //Module* M = EXTLLVM::I()->M;
    char name[1024];
    sprintf(name,"%s_native",string_value(pair_car(Args)));
    llvm::Function* func = extemp::EXTLLVM::I()->getFunction(name);
    if(func == 0)
      {
        return Scheme->F;
      }
    // this should be safe without a lock
    void* p = EXTLLVM::I()->EE->getPointerToFunction(func);

    if(p==NULL) {
            //[[LogView sharedInstance] error:@"LLVM: Bad Function Ptr\n"];
            return Scheme->F;
    }

    void(*f)(void) = (void(*)(void)) p;
    f();

    return Scheme->T;
  }

    //
    // This will not be threadsafe whenever a bind-func is done!
    //
    pointer call_compiled(scheme* Scheme, pointer Args)
    {
        using namespace llvm;

        ExecutionEngine* EE = EXTLLVM::I()->EE;

#ifdef LLVM_EE_LOCK
  llvm::MutexGuard locked(EE->lock);
#endif

        llvm::Function* func = (Function*) cptr_value(pair_car(Args));
        if(func == 0)
        {
            printf("No such function\n");
            return Scheme->F;
        }
        func->getArgumentList();
        Args = pair_cdr(Args);
        int lgth = list_length(Scheme, Args);
        Function::ArgumentListType::iterator funcargs = func->getArgumentList().begin();
        if(lgth != func->getArgumentList().size())
        {
            printf("Wrong number of arguments for function!\n");
            return Scheme->F;
        }
        std::vector<llvm::GenericValue> fargs(lgth);
        //std::cout << "ARGS: " << lgth << std::endl;
        for(int i=0;i<lgth;i++,++funcargs)
        {
            Argument* a = &*funcargs;
            pointer p = list_ref(Scheme, i, Args);
            if(is_integer(p)) {
                if(a->getType()->getTypeID() != Type::IntegerTyID)
                {
                    printf("Bad argument type %i\n",i);
                    return Scheme->F;
                }
                int width = a->getType()->getPrimitiveSizeInBits();
                //std::cout << "TYPE: " << a->getType()->getTypeID() << std::endl;
                fargs[i].IntVal = APInt(width,ivalue(p));
            }
            else if(is_real(p))
            {

                if(a->getType()->getTypeID() == Type::FloatTyID)
                {
                    fargs[i].FloatVal = (float) rvalue(p);
                }
                else if(a->getType()->getTypeID() == Type::DoubleTyID)
                {
                    fargs[i].DoubleVal = rvalue(p);
                }
                else
                {
                    printf("Bad argument type %i\n",i);
                    return Scheme->F;
                }
            }
            else if(is_string(p))
            {
                if(a->getType()->getTypeID() != Type::PointerTyID)
                {
                    printf("Bad argument type %i\n",i);
                    return Scheme->F;
                }
                //std::cout << "PTRVALUE: " << cptr_value(p) << std::endl;
                fargs[i].PointerVal = string_value(p);
            }
            else if(is_cptr(p))
            {
                if(a->getType()->getTypeID() != Type::PointerTyID)
                {
                    printf("Bad argument type %i\n",i);
                    return Scheme->F;
                }
                fargs[i].PointerVal = cptr_value(p);
                //fargs[i].PointerVal = (void*)p;
            }
            else if(is_closure(p))
            {
                //ascii_print_color(1,1,10); // error color
                printf("Bad argument at index %i you can't pass in a scheme closure.\n",i);
                //ascii_print_color(0,9,10);
                return Scheme->F;
            }
            else {
                //ascii_print_color(1,1,10); // error color
                printf("Bad argument at index %i\n",i);
                //ascii_print_color(0,9,10); // default
                return Scheme->F;
            }

        }
  GenericValue gv = EE->runFunction(func,fargs);

        //std::cout << "GV: " << gv.DoubleVal << " " << gv.FloatVal << " " << gv.IntVal.getZExtValue() << std::endl;
        switch(func->getReturnType()->getTypeID())
        {
        case Type::FloatTyID:
            return mk_real(Scheme, gv.FloatVal);
        case Type::DoubleTyID:
            return mk_real(Scheme, gv.DoubleVal);
        case Type::IntegerTyID:
            return mk_integer(Scheme, gv.IntVal.getZExtValue()); //  getRawData());
        case Type::PointerTyID:
            return mk_cptr(Scheme, gv.PointerVal);
        case Type::VoidTyID:
            return Scheme->T;
        default:
            return Scheme->F;
        }
    }

    // this all here to conver 32bit floats (as a string) into llvms hex float 32 notation :(
    pointer llvm_convert_float_constant(scheme* Scheme, pointer Args)
    {
        char* floatin = string_value(pair_car(Args));
        char floatout[256];
        // if already converted to hex value just return Hex String Unchanged
        if(floatin[1]=='x') return pair_car(Args);
#ifdef _WIN32
        float f = (float) strtod(floatin, (char**) &floatout);
#else
        float f = strtof(floatin, (char**) &floatout);
#endif
        llvm::APFloat apf(f);

        bool ignored;
        bool isDouble = false; // apf.getSemantics() == &llvm::APFloat::IEEEdouble;
        double Val = isDouble ? apf.convertToDouble() :
        apf.convertToFloat();
        // char hexstr[128];
        // apf.convertToHexString(hexstr,0,false,llvm::APFloat::rmTowardZero);
        // std::string StrVal(hexstr);
        std::string StrVal = xtm_ftostr(apf);

        // Check to make sure that the stringized number is not some string like
        // "Inf" or NaN, that atof will accept, but the lexer will not.  Check
        // that the string matches the "[-+]?[0-9]" regex.
        //
        if ((StrVal[0] >= '0' && StrVal[0] <= '9') ||
            ((StrVal[0] == '-' || StrVal[0] == '+') &&
             (StrVal[1] >= '0' && StrVal[1] <= '9'))) {
            // Reparse stringized version!
            if (atof(StrVal.c_str()) == Val) {
              return mk_string(Scheme, StrVal.c_str());
            }
        }

        // Otherwise we could not reparse it to exactly the same value, so we must
        // output the string in hexadecimal format!  Note that loading and storing
        // floating point types changes the bits of NaNs on some hosts, notably
        // x86, so we must not use these types.
        assert(sizeof(double) == sizeof(uint64_t) && "assuming that double is 64 bits!");
        char Buffer[40];
        //APFloat apf = CFP->getValueAPF();
        // Floats are represented in ASCII IR as double, convert.
        //if (!isDouble) apf.convert(llvm::APFloat::IEEEdouble, llvm::APFloat::rmNearestTiesToEven, &ignored);
        apf.convert(llvm::APFloat::IEEEdouble, llvm::APFloat::rmNearestTiesToEven, &ignored);

        char tmpstr[256];
        tmpstr[0] = '0';
        tmpstr[1] = 'x';
        tmpstr[2] = 0;
        char* v = llvm::utohex_buffer(uint64_t(apf.bitcastToAPInt().getZExtValue()), Buffer+40);
        strcat(tmpstr, v);
        //std::cout << "STR: " << tmpstr << "  v: " << v <<  std::endl;
        return mk_string(Scheme, tmpstr);
    }


     // this all here to conver 64bit floats (as a string) into llvms hex floating point notation :(
     pointer llvm_convert_double_constant(scheme* Scheme, pointer Args)
     {
        char* floatin = string_value(pair_car(Args));
        char floatout[256];
        // if already converted to hex value just return Hex String Unchanged
        if(floatin[1]=='x') return pair_car(Args);
 #ifdef _WIN32
        double f = strtod(floatin, (char**) &floatout);
 #else
        double f = strtod(floatin, (char**) &floatout);
 #endif
        llvm::APFloat apf(f);

        bool ignored;
        bool isDouble = true; // apf.getSemantics() == &llvm::APFloat::IEEEdouble;
        double Val = isDouble ? apf.convertToDouble() : apf.convertToFloat();

        // char hexstr[128];
        // apf.convertToHexString(hexstr,0,false,llvm::APFloat::rmTowardZero);
        // std::string StrVal(hexstr);
        std::string StrVal = xtm_ftostr(apf);

        // Check to make sure that the stringized number is not some string like
        // "Inf" or NaN, that atof will accept, but the lexer will not.  Check
        // that the string matches the "[-+]?[0-9]" regex.
        //
        if ((StrVal[0] >= '0' && StrVal[0] <= '9') ||
            ((StrVal[0] == '-' || StrVal[0] == '+') &&
             (StrVal[1] >= '0' && StrVal[1] <= '9'))) {
            // Reparse stringized version!
            if (atof(StrVal.c_str()) == Val) {
                return mk_string(Scheme, StrVal.c_str());
            }
        }

        // Otherwise we could not reparse it to exactly the same value, so we must
        // output the string in hexadecimal format!  Note that loading and storing
        // floating point types changes the bits of NaNs on some hosts, notably
        // x86, so we must not use these types.
        assert(sizeof(double) == sizeof(uint64_t) && "assuming that double is 64 bits!");
        char Buffer[40];
        //APFloat apf = CFP->getValueAPF();
        // Floats are represented in ASCII IR as double, convert.
        //if (!isDouble) apf.convert(llvm::APFloat::IEEEdouble, llvm::APFloat::rmNearestTiesToEven, &ignored);
        //apf.convert(llvm::APFloat::IEEEdouble, llvm::APFloat::rmNearestTiesToEven, &ignored);

        char tmpstr[256];
        tmpstr[0] = '0';
        tmpstr[1] = 'x';
        tmpstr[2] = 0;
        char* v = llvm::utohex_buffer(uint64_t(apf.bitcastToAPInt().getZExtValue()), Buffer+40);
        strcat(tmpstr, v);
        //std::cout << "STR: " << tmpstr << "  v: " << v <<  std::endl;
        return mk_string(Scheme, tmpstr);
     }


    pointer llvm_count_set(scheme* Scheme, pointer Args)
    {
        EXTLLVM::LLVM_COUNT = ivalue(pair_car(Args));
        return mk_integer(Scheme, EXTLLVM::LLVM_COUNT);
    }


    pointer llvm_count_inc(scheme* Scheme, pointer Args)
    {
        EXTLLVM::LLVM_COUNT++;
        return mk_integer(Scheme, EXTLLVM::LLVM_COUNT);
    }

    pointer llvm_count(scheme* Scheme, pointer Args)
    {
        return mk_integer(Scheme, EXTLLVM::LLVM_COUNT);
    }

    pointer printLLVMModule(scheme* Scheme, pointer Args)
    {
        llvm::Module* M = EXTLLVM::I()->M;
        std::string str;
        llvm::raw_string_ostream ss(str);

        if(list_length(Scheme, Args) > 0) {
            const llvm::GlobalValue* val = extemp::EXTLLVM::I()->getGlobalValue(string_value(pair_car(Args)));
    //llvm::GlobalValue* val = M->getNamedValue(std::string(string_value(pair_car(Args))));
            if(val == NULL) {
                std::cerr << "No such value found in LLVM Module" << std::endl;
                return Scheme->F;
            }
            ss << *val;
            printf("At address: %p\n%s\n",val,str.c_str());
        } else {
            ss << *M;
        }

        printf("%s",str.c_str());
        return Scheme->T;
    }

pointer printLLVMFunction(scheme* Scheme, pointer Args)
{
  llvm::Function* func = extemp::EXTLLVM::I()->getFunction(string_value(pair_car(Args)));
        std::string str;
        llvm::raw_string_ostream ss(str);
        ss << *func;
        printf("%s",str.c_str());
        return Scheme->T;
}


  pointer bind_symbol(scheme* Scheme, pointer Args)
  {
    void* library = cptr_value(pair_car(Args));
    char* symname = string_value(pair_cadr(Args));

    llvm::Module* M = EXTLLVM::I()->M;
    llvm::ExecutionEngine* EE = EXTLLVM::I()->EE;

    llvm::MutexGuard locked(EE->lock);

#ifdef _WIN32
    void* ptr = (void*) GetProcAddress((HMODULE)library, symname);
#else
    void* ptr = dlsym(library, symname);
#endif
    if(ptr) {
      EE->updateGlobalMapping(symname, (uint64_t)ptr);
      return Scheme->T;
    }else{
      // printf("Could not find symbol named %s\n",symname);
      return Scheme->F;
    }
  }

  pointer update_mapping(scheme* Scheme, pointer Args)
  {
    char* symname = string_value(pair_car(Args));
    void* ptr = cptr_value(pair_cadr(Args));

    llvm::Module* M = EXTLLVM::I()->M;
    llvm::ExecutionEngine* EE = EXTLLVM::I()->EE;

    llvm::MutexGuard locked(EE->lock);

    // returns previous value of the mapping, or NULL if not set
    uint64_t oldval = EE->updateGlobalMapping(symname, (uint64_t)ptr);
    return mk_cptr(Scheme, (void*)oldval);
  }

    // For simple preprocessor alias's
pointer add_llvm_alias(scheme* Scheme, pointer Args)
{
    LLVM_ALIAS_TABLE[string_value(pair_car(Args))] = string_value(pair_cadr(Args));
    return Scheme->T;
}

pointer get_llvm_alias(scheme* Scheme, pointer Args)
{
    char* name = string_value(pair_car(Args));
    auto iter(LLVM_ALIAS_TABLE.find(std::string(string_value(pair_car(Args)))));
    if (iter != LLVM_ALIAS_TABLE.end()) {
        return mk_string(Scheme, iter->second.c_str());
    }
    return Scheme->F;
}

pointer get_named_type(scheme* Scheme, pointer Args)
{
        char* n = string_value(pair_car(Args));
        char nk[256];
        char* name = nk;
        strcpy(name,n);
        if (name[0] == '%') name = name+1;

        int ptrdepth = 0;
        while(name[strlen(name)-1] == '*') {
          name[strlen(name)-1]='\0';
    ptrdepth++;
        }

        //llvm::Module* M = EXTLLVM::I()->M;
        //const llvm::Type* tt = M->getTypeByName(name);
  const llvm::Type* tt = extemp::EXTLLVM::I()->getNamedType(name);

        if(tt) {
          //return mk_string(Scheme,M->getTypeName(tt).c_str());
          std::string typestr;
          llvm::raw_string_ostream ss(typestr);
          tt->print(ss);


          const char* tmp_name = ss.str().c_str();
          if(tt->isStructTy()) {
            const char* eq_type_string = " = type ";
            rsplit((char*)eq_type_string,(char*)tmp_name,tmp_str_a,tmp_str_b);
            tmp_name = tmp_str_b;
          }

          //add back any requried '*'s
          if(ptrdepth>0) {
            char tmpstr[256];
            strcpy(tmpstr,tmp_name);
            auto len(strlen(tmpstr));
            for( ;ptrdepth>0;ptrdepth--, ++len) {
              tmpstr[len]='*';
            }
            tmpstr[len] = '\0';
            tmp_name = tmpstr;
          }
          return mk_string(Scheme,tmp_name);
        } else {
          return Scheme->NIL;
        }
}

  pointer getClockTime(scheme* Scheme, pointer Args)
  {
    return mk_real(Scheme, getRealTime()+UNIV::CLOCK_OFFSET);
  }

  pointer adjustClockOffset(scheme* Scheme, pointer Args)
  {
    UNIV::CLOCK_OFFSET = rvalue(pair_car(Args)) + UNIV::CLOCK_OFFSET;
    return mk_real(Scheme,UNIV::CLOCK_OFFSET);
  }

  pointer setClockOffset(scheme* Scheme, pointer Args)
  {
    UNIV::CLOCK_OFFSET = rvalue(pair_car(Args));
    return pair_car(Args);
  }

  pointer getClockOffset(scheme* Scheme, pointer Args)
  {
    return mk_real(Scheme, UNIV::CLOCK_OFFSET);
  }

  pointer lastSampleBlockClock(scheme* Scheme, pointer Args)
  {
    pointer p1 = mk_integer(Scheme,UNIV::TIME);
    EnvInjector(Scheme, p1);
    pointer p2 = mk_real(Scheme,AudioDevice::REALTIME + UNIV::CLOCK_OFFSET);
    EnvInjector(Scheme, p2);
    pointer p3 = cons(Scheme, p1, p2);
    return p3;
  }

}

} // end namespace

