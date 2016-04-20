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

#ifndef _SCHEME_FFI_H
#define _SCHEME_FFI_H

#include "Scheme.h"
#include "EXTLLVM.h"
#include "Task.h"

namespace extemp {

namespace SchemeFFI {

void initSchemeFFI(scheme* _sc);
void addGlobal(scheme* sc, char* symbol_name, pointer arg);
void addForeignFunc(scheme* sc, char* symbol_name, foreign_func func);
void addGlobalCptr(scheme* sc, char* symbol_name, void* ptr);

// memory zone stuff
void freeWithDelay(TaskI* task);
void destroyMallocZoneWithDelay(TaskI* task);

// llvm stuff
pointer optimizeCompiles(scheme* _sc, pointer args);
pointer fastCompiles(scheme* _sc, pointer args);
pointer backgroundCompiles(scheme* _sc, pointer args);
pointer verifyCompiles(scheme* _sc, pointer args);
pointer jitCompileIRString(scheme* _sc, pointer args);
pointer ff_set_name(scheme* _sc, pointer args);
pointer ff_get_name(scheme* _sc, pointer args);
pointer get_function(scheme* _sc, pointer args);
pointer get_globalvar(scheme* _sc, pointer args);
pointer get_struct_size(scheme* _sc, pointer args);
pointer get_named_struct_size(scheme* _sc, pointer args);
pointer get_function_args(scheme* _sc, pointer args);
pointer get_function_varargs(scheme* _sc, pointer args);
pointer get_function_type(scheme* _sc, pointer args);
pointer get_function_calling_conv(scheme* _sc, pointer args);
pointer get_global_variable_type(scheme* _sc, pointer args);
pointer get_function_pointer(scheme* _sc, pointer args);
pointer remove_function(scheme* _sc, pointer args);
pointer remove_global_var(scheme* _sc, pointer args);
pointer erase_function(scheme* _sc, pointer args);
pointer llvm_call_void_native(scheme* _sc, pointer args);
pointer call_compiled(scheme* _sc, pointer args);
pointer llvm_convert_float_constant(scheme* _sc, pointer args);
pointer llvm_convert_double_constant(scheme* _sc, pointer args);
pointer llvm_count(scheme* _sc, pointer args);
pointer llvm_count_set(scheme* _sc, pointer args);
pointer llvm_count_inc(scheme* _sc, pointer args);
pointer llvm_print_all_closures(scheme* _sc, pointer args);
pointer llvm_print_closure(scheme* _sc, pointer args);
pointer llvm_closure_last_name(scheme* _sc, pointer args);
pointer llvm_disasm(scheme* _sc, pointer args);
pointer callClosure(scheme* _sc, pointer args);
pointer printLLVMModule(scheme* _sc, pointer args);
pointer printLLVMFunction(scheme* _sc, pointer args);
pointer bind_symbol(scheme* _sc, pointer args);
pointer update_mapping(scheme* _sc, pointer args);
pointer get_named_type(scheme* _sc, pointer args);
pointer get_global_module(scheme* _sc, pointer args);

pointer export_llvmmodule_bitcode(scheme* _sc, pointer args);
pointer add_llvm_alias(scheme* _sc, pointer args);
pointer get_llvm_alias(scheme* _sc, pointer args);
pointer impcirGetName(scheme* _sc, pointer args);
pointer impcirGetType(scheme* _sc, pointer args);
pointer impcirAdd(scheme* _sc, pointer args);

// clock
pointer getClockTime(scheme* _sc, pointer args);
pointer adjustClockOffset(scheme* _sc, pointer args);
pointer setClockOffset(scheme* _sc, pointer args);
pointer getClockOffset(scheme* _sc, pointer args);
pointer lastSampleBlockClock(scheme* _sc, pointer args);

}

} // end namespace

#endif
