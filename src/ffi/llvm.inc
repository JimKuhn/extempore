pointer optimizeCompiles(scheme* Scheme, pointer Args)
{
    EXTLLVM::OPTIMIZE_COMPILES = (pair_car(Args) == Scheme->T);
    return Scheme->T;
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
   llvm_scheme_ff_set_name(ff, name);
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
    auto func(extemp::EXTLLVM::I()->getFunction(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    return mk_cptr(Scheme, const_cast<llvm::Function*>(func));
}

pointer get_globalvar(scheme* Scheme, pointer Args)
{
    auto var(extemp::EXTLLVM::I()->getGlobalVariable(string_value(pair_car(Args))));
    if (!var) {
        return Scheme->F;
    }
    return mk_cptr(Scheme, const_cast<llvm::GlobalVariable*>(var));
}

pointer get_struct_size(scheme* Scheme, pointer Args)
{
    char* struct_type_str = string_value(pair_car(Args));
    unsigned long long hash = string_hash(reinterpret_cast<unsigned char*>(struct_type_str));
    char name[128];
    sprintf(name,"_xtmT%lld",hash);
    char assm[1024];
    sprintf(assm,"%%%s = type %s",name,struct_type_str);

    llvm::SMDiagnostic pa;
    auto newM(llvm::parseAssemblyString(assm, pa, llvm::getGlobalContext()));
    if (!newM) {
        return Scheme->F;
    }
    auto type(newM->getTypeByName(name));
    if (!type) {
        return Scheme->F;
    }
    auto layout(new llvm::DataLayout(newM.get()));
    long size = layout->getStructLayout(type)->getSizeInBytes();
    delete layout;
    return mk_integer(Scheme, size);
}

pointer get_named_struct_size(scheme* Scheme, pointer Args)
{
    llvm::Module* M = EXTLLVM::I()->M;
    auto type(extemp::EXTLLVM::I()->getNamedType(string_value(pair_car(Args))));
    if (!type) {
        return Scheme->F;
    }
    auto layout(new llvm::DataLayout(M));
    long size = layout->getStructLayout(type)->getSizeInBytes();
    delete layout;
    return mk_integer(Scheme, size);
}

static char tmp_str_a[1024];
static char tmp_str_b[4096];

pointer get_function_args(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM::I()->getFunction(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    std::string typestr;
    llvm::raw_string_ostream ss(typestr);
    func->getReturnType()->print(ss);
    const char* tmp_name = ss.str().c_str();
    const char* eq_type_string = " = type ";
    if (func->getReturnType()->isStructTy()) {
        rsplit(eq_type_string, tmp_name, tmp_str_a, tmp_str_b);
        tmp_name = tmp_str_a;
    }
    pointer str = mk_string(Scheme, tmp_name);
    pointer p = cons(Scheme, str, Scheme->NIL);
    for (const auto& arg : func->getArgumentList()) {
        {
            EnvInjector injector(Scheme, p);
            std::string typestr2;
            llvm::raw_string_ostream ss2(typestr2);
            arg.getType()->print(ss2);
            tmp_name = ss2.str().c_str();
            if (arg.getType()->isStructTy()) {
                rsplit(eq_type_string, tmp_name, tmp_str_a, tmp_str_b);
                tmp_name = tmp_str_a;
            }
            pointer str = mk_string(Scheme, tmp_name);
        }
        p = cons(Scheme, str, p);
    }
    return reverse_in_place(Scheme, Scheme->NIL, p);
}

pointer get_function_varargs(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM::I()->getFunction(string_value(pair_car(Args))));
    return (func && func->isVarArg()) ? Scheme->T : Scheme->F;
}

pointer get_function_type(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM::I()->getFunction(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    std::string typestr;
    llvm::raw_string_ostream ss(typestr);
    func->getFunctionType()->print(ss);
    return mk_string(Scheme, ss.str().c_str());
}

pointer get_function_calling_conv(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM::I()->getFunction(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    return mk_integer(Scheme, func->getCallingConv());
}

pointer get_global_variable_type(scheme* Scheme, pointer Args)
{
    using namespace llvm;
    auto var(extemp::EXTLLVM::I()->getGlobalVariable(string_value(pair_car(Args))));
    if (!var) {
        return Scheme->F;
    }
    std::string typestr;
    llvm::raw_string_ostream ss(typestr);
    var->getType()->print(ss);
    return mk_string(Scheme, ss.str().c_str());
}

pointer get_function_pointer(scheme* Scheme, pointer Args)
{
    auto name(string_value(pair_car(Args)));
    void* p = EXTLLVM::I()->EE->getPointerToGlobalIfAvailable(name);
    if (!p) { // look for it as a JIT-compiled function
        p = reinterpret_cast<void*>(EXTLLVM::I()->EE->getFunctionAddress(name));
        if (!p) {
            return Scheme->F;
        }
    }
    return mk_cptr(Scheme, p);
}

pointer remove_function(scheme* Scheme, pointer Args)
{
    auto func(EXTLLVM::I()->EE->FindFunctionNamed(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    if (func->mayBeOverridden()) {
        func->dropAllReferences();
        func->removeFromParent();
        return Scheme->T;
    }
    printf("Cannot remove function with dependencies\n");
    return Scheme->F;
}

pointer remove_global_var(scheme* Scheme, pointer Args)
{
    auto var(EXTLLVM::I()->EE->FindGlobalVariableNamed(string_value(pair_car(Args))));
    if (!var) {
        return Scheme->F;
    }
    var->dropAllReferences();
    var->removeFromParent();
    return Scheme->T;
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

pointer llvm_call_void_native(scheme* Scheme, pointer Args)
{
    char name[1024];
    strcpy(name, string_value(pair_car(Args)));
    strcat(name, "_native");
    auto func(EXTLLVM::I()->EE->FindFunctionNamed(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    void* p = EXTLLVM::I()->EE->getPointerToFunction(func);
    if (!p) {
        return Scheme->F;
    }
    ((void(*)(void)) p)();
    return Scheme->T;
}

pointer call_compiled(scheme* Scheme, pointer Args)
{
    llvm::ExecutionEngine* EE = EXTLLVM::I()->EE;
#ifdef LLVM_EE_LOCK
    llvm::MutexGuard locked(EE->lock);
#endif
    auto func(reinterpret_cast<llvm::Function*>(cptr_value(pair_car(Args))));
    if (unlikely(!func)) {
        printf("No such function\n");
        return Scheme->F;
    }
    func->getArgumentList();
    Args = pair_cdr(Args);
    int lgth = list_length(Scheme, Args);
    if (unlikely(lgth != func->getArgumentList().size())) {
        printf("Wrong number of arguments for function!\n");
        return Scheme->F;
    }
    int i = 0;
    std::vector<llvm::GenericValue> fargs(lgth);
    for (const auto& arg : func->getArgumentList()) {
        pointer p = list_ref(Scheme, i++, Args);
        if (is_integer(p)) {
            if (unlikely(arg.getType()->getTypeID() != llvm::Type::IntegerTyID)) {
                printf("Bad argument type %i\n",i);
                return Scheme->F;
            }
            int width = arg.getType()->getPrimitiveSizeInBits();
            fargs[i].IntVal = llvm::APInt(width, ivalue(p));
        } else if (is_real(p)) {
            if (arg.getType()->getTypeID() == llvm::Type::FloatTyID) {
                fargs[i].FloatVal = rvalue(p);
            } else if (arg.getType()->getTypeID() == llvm::Type::DoubleTyID) {
                fargs[i].DoubleVal = rvalue(p);
            } else {
                printf("Bad argument type %i\n",i);
                return Scheme->F;
            }
        } else if (is_string(p)) {
            if (unlikely(arg.getType()->getTypeID() != llvm::Type::PointerTyID)) {
                printf("Bad argument type %i\n",i);
                return Scheme->F;
            }
            fargs[i].PointerVal = string_value(p);
        } else if (is_cptr(p)) {
            if (unlikely(arg.getType()->getTypeID() != llvm::Type::PointerTyID)) {
                printf("Bad argument type %i\n",i);
                return Scheme->F;
            }
            fargs[i].PointerVal = cptr_value(p);
        } else if (unlikely(is_closure(p))) {
            printf("Bad argument at index %i you can't pass in a scheme closure.\n",i);
            return Scheme->F;
        } else {
            printf("Bad argument at index %i\n",i);
            return Scheme->F;
        }
    }
    llvm::GenericValue gv = EE->runFunction(func, fargs);
    switch(func->getReturnType()->getTypeID()) {
    case llvm::Type::FloatTyID:
        return mk_real(Scheme, gv.FloatVal);
    case llvm::Type::DoubleTyID:
        return mk_real(Scheme, gv.DoubleVal);
    case llvm::Type::IntegerTyID:
        return mk_integer(Scheme, gv.IntVal.getZExtValue()); //  getRawData());
    case llvm::Type::PointerTyID:
        return mk_cptr(Scheme, gv.PointerVal);
    case llvm::Type::VoidTyID:
        return Scheme->T;
    default:
        return Scheme->F;
    }
}

pointer llvm_convert_float_constant(scheme* Scheme, pointer Args)
{
    char* floatin = string_value(pair_car(Args));
    if (floatin[1] == 'x') {
        return pair_car(Args);
    }
    llvm::APFloat apf(llvm::APFloat::IEEEsingle, llvm::StringRef(floatin));
    // TODO: if necessary, checks for inf/nan can be done here
    auto ival(llvm::APInt::doubleToBits(apf.convertToFloat()));
    return mk_string(Scheme, (std::string("0x") + llvm::utohexstr(ival.getLimitedValue(), true)).c_str());
}

pointer llvm_convert_double_constant(scheme* Scheme, pointer Args)
{
    static_assert(sizeof(double) == sizeof(uint64_t), "sizeof(double) must be 8 bytes");
    char* floatin = string_value(pair_car(Args));
    if (floatin[1] == 'x') {
        return pair_car(Args);
    }
    llvm::APFloat apf(llvm::APFloat::IEEEdouble, llvm::StringRef(floatin));
    // TODO: if necessary, checks for inf/nan can be done here
    auto ival(llvm::APInt::doubleToBits(apf.convertToFloat()));
    return mk_string(Scheme, (std::string("0x") + llvm::utohexstr(ival.getLimitedValue(), true)).c_str());
}

pointer llvm_count(scheme* Scheme, pointer Args)
{
    return mk_integer(Scheme, EXTLLVM::LLVM_COUNT);
}

pointer llvm_count_set(scheme* Scheme, pointer Args)
{
    EXTLLVM::LLVM_COUNT = ivalue(pair_car(Args));
    return llvm_count(Scheme, Args);
}

pointer llvm_count_inc(scheme* Scheme, pointer Args)
{
    ++EXTLLVM::LLVM_COUNT;
    return llvm_count(Scheme, Args);
}

pointer callClosure(scheme* Scheme, pointer Args)
{
    using namespace llvm;
    uint32_t** closure = (uint32_t**) cptr_value(pair_car(Args));
    void* eptr = closure[0];
    int64_t (*fptr)(void*, int64_t) = (int64_t (*)(void*, int64_t)) closure[0];
    return mk_integer(Scheme, (*fptr)(eptr, ivalue(pair_cadr(Args))));
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
    auto func(extemp::EXTLLVM::I()->getFunction(string_value(pair_car(Args))));
    std::string str;
    llvm::raw_string_ostream ss(str);
    ss << *func;
    puts(str.c_str());
    return Scheme->T;
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

#define LLVM_DEFS \
        { "llvm:optimize", &optimizeCompiles }, \
        { "llvm:jit-compile-ir-string", &jitCompileIRString}, \
        { "llvm:ffi-set-name", &ff_set_name }, \
        { "llvm:ffi-get-name", &ff_get_name }, \
        { "llvm:get-function", &get_function }, \
        { "llvm:get-globalvar", &get_globalvar }, \
        { "llvm:get-struct-size", &get_struct_size }, \
        { "llvm:get-named-struct-size", &get_named_struct_size }, \
        { "llvm:get-function-args", &get_function_args }, \
        { "llvm:get-function-varargs", &get_function_varargs }, \
        { "llvm:get-function-type", &get_function_type }, \
        { "llvm:get-function-calling-conv", &get_function_calling_conv }, \
        { "llvm:get-global-variable-type", &get_global_variable_type }, \
        { "llvm:get-function-pointer", &get_function_pointer }, \
        { "llvm:remove-function", &remove_function }, \
        { "llvm:remove-globalvar", &remove_global_var }, \
        { "llvm:erase-function", &erase_function }, \
        { "llvm:call-void-func", &llvm_call_void_native }, \
        { "llvm:run", &call_compiled }, \
        { "llvm:convert-float", &llvm_convert_float_constant }, \
        { "llvm:convert-double", &llvm_convert_double_constant }, \
        { "llvm:count", &llvm_count }, \
        { "llvm:count-set", &llvm_count_set }, \
        { "llvm:count++", &llvm_count_inc }, \
        { "llvm:call-closure", &callClosure }, \
        { "llvm:print", &printLLVMModule }, \
        { "llvm:print-function", &printLLVMFunction }, \
        { "llvm:print-all-closures", &llvm_print_all_closures }, \
        { "llvm:print-closure", &llvm_print_closure }, \
        { "llvm:get-closure-work-name", &llvm_closure_last_name }, \
        { "llvm:disassemble", &llvm_disasm }, \
        { "llvm:bind-symbol", &bind_symbol }, \
        { "llvm:update-mapping", &update_mapping }, \
        { "llvm:add-llvm-alias", &add_llvm_alias }, \
        { "llvm:get-llvm-alias", &get_llvm_alias }, \
        { "llvm:get-named-type", &get_named_type }, \
        { "llvm:get-global-module", &get_global_module }, \
        { "llvm:export-module", &export_llvmmodule_bitcode }
