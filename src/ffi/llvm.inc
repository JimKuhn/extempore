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
    llvm::Function* func = extemp::EXTLLVM::I()->getFunction(string_value(pair_car(Args)));
    if (!func) {
        return Scheme->F;
    }
    return mk_cptr(Scheme, func);
}

pointer get_globalvar(scheme* Scheme, pointer Args)
{
    llvm::GlobalVariable* var = extemp::EXTLLVM::I()->getGlobalVariable(string_value(pair_car(Args)));
    if (!var) {
        return Scheme->F;
    }
    return mk_cptr(Scheme, var);
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

    pointer llvm_count(scheme* Scheme, pointer Args)
    {
        return mk_integer(Scheme, EXTLLVM::LLVM_COUNT);
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

    pointer callClosure(scheme* Scheme, pointer Args)
    {
        using namespace llvm;
        uint32_t** closure = (uint32_t**) cptr_value(pair_car(Args));
        void* eptr = (void*) *(closure+0);
        int64_t (*fptr)(void*, int64_t) = (int64_t (*)(void*, int64_t)) *(closure+1);
        return mk_integer(Scheme, (*fptr)(eptr,ivalue(pair_cadr(Args))));
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
        { "llvm:fast-compile", &fastCompiles }, \
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
