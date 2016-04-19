static pointer asciiColor(scheme* Scheme, pointer Args)
{
    ascii_text_color(ivalue(pair_car(Args)),ivalue(pair_cadr(Args)),ivalue(pair_caddr(Args)));
    return Scheme->T;
}

static pointer emit(scheme* Scheme, pointer Args)
{
    std::stringstream ss;
    int lgth = list_length(Scheme, Args);
    pointer io = list_ref(Scheme, lgth - 1, Args);
    if (!is_string(io)) {
        PRINT_ERROR("Emit accepts only string arguments!\n");
        return Scheme->F;
    }
    ss << string_value(io);
    pointer arg = 0;
    for (int i=0; i < lgth - 1; ++i) {
        arg = pair_car(Args);
        if (!is_string(arg)) {
            PRINT_ERROR("Emit accepts only string arguments!\n");
            return Scheme->F;
        }
        ss << string_value(arg);
        Args = pair_cdr(Args);
    }
    auto tmp(ss.str());
    int l = tmp.length();
    auto s(strdup(tmp.c_str()));
    free(io->_object._string._svalue);
    io->_object._string._svalue = s;
    io->_object._string._length = l;
    return io;
}

static pointer exit_extempore(scheme* Scheme, pointer Args)
{
    int rc(ivalue(pair_car(Args)));
#ifdef _WIN32
    std::exit(rc);
#else
    std::_Exit(rc);
#endif
}

// ipc stuff
static pointer newSchemeProcess(scheme* Scheme, pointer Args)
{
    std::string proc_name(string_value(pair_car(Args)));
    int port = ivalue(pair_cadr(Args));
    SchemeProcess* sp = new SchemeProcess(UNIV::SHARE_DIR, proc_name, port, 0);
    sp->start();
    SchemeREPL* repl = new SchemeREPL(proc_name);
    if (repl->connectToProcessAtHostname("localhost", port)) {
        return Scheme->T;
    }
    sp->stop();
    delete sp;
    delete repl;
    return Scheme->F;
}

static pointer connectToProcess(scheme* Scheme, pointer Args)
{
    std::string host_name(string_value(pair_car(Args)));
    std::string proc_name(string_value(pair_cadr(Args)));
    int port = ivalue(pair_caddr(Args));
    SchemeREPL* repl = new SchemeREPL(proc_name);
    if (repl->connectToProcessAtHostname(host_name, port)) {
        return Scheme->T;
    }
    delete repl;
    return Scheme->F;
}

static SchemeREPL* findREPL(const std::string& Name)
{
    auto repl(SchemeREPL::I(Name));
    if (unlikely(!repl)) {
      std::cout << "Error: unknown scheme process '" << Name << "'" << std::endl;
      return nullptr;
   }
   return repl;
}

static bool appendArg(scheme* Scheme, std::stringstream& Stream, pointer Value)
{
    Stream << ' ';
    if (is_pair(Value) || is_vector(Value) || is_symbol(Value)) {
        Stream << "'";
        UNIV::printSchemeCell(Scheme, Stream, Value,true);
    } else if (Scheme->NIL == Value) {
        Stream << "'()";
    } else if (Value == Scheme->F) {
        Stream << "#f";
    } else if (Value == Scheme->T) {
        Stream << "#t";
    } else if (Value == Scheme->EOF_OBJ) {
        // ignore end of file
    } else if (is_closure(Value)) {
        std::stringstream tmp;
        UNIV::printSchemeCell(Scheme, tmp, closure_code(Value), true);
        Stream << "(lambda " << tmp.str().substr(1);
    } else if (is_string(Value) || is_number(Value) || is_symbol(Value)) {
        UNIV::printSchemeCell(Scheme, Stream, Value, true);
    } else {
        PRINT_ERROR("Extempore's IPC mechanism cannot serialise this type - this maybe related to the return type as well as the arguments.\n");
        return false;
    }
    return true;
}

static pointer ipcCall(scheme* Scheme, pointer Args)
{
    auto repl(findREPL(string_value(pair_car(Args))));
    if (!repl) {
      return Scheme->F;
    }
    std::stringstream ss;
    pointer sym = pair_cadr(Args);
    Args = pair_cddr(Args);
    for (; is_pair(Args); Args = pair_cdr(Args)) {
        pointer value = pair_car(Args);
        if (!appendArg(Scheme, ss, pair_car(Args))) {
            return Scheme->F;
        }
    }
    repl->writeString(std::string("(") + symname(sym) + ss.str() + ')');
    return Scheme->T;
}

pointer ipcDefine(scheme* Scheme, pointer Args)
{
    auto repl(findREPL(string_value(pair_car(Args))));
    if (!repl) {
        return Scheme->F;
    }
    std::stringstream ss;
    pointer sym = pair_cadr(Args);
    if (!appendArg(Scheme, ss, pair_caddr(Args))) {
        return Scheme->F;
    }
    repl->writeString(std::string("(") + symname(sym) + ss.str() +')');
    return Scheme->T;
}

pointer ipcEval(scheme* Scheme, pointer Args)
{
    auto repl(findREPL(string_value(pair_car(Args))));
    if (!repl) {
        return Scheme->F;
    }
    repl->writeString(string_value(pair_cadr(Args)));
    return Scheme->T;
}

pointer ipcLoad(scheme* Scheme, pointer Args)
{
    auto repl(findREPL(string_value(pair_car(Args))));
    if (!repl) {
      return Scheme->F;
    }
    repl->writeString(std::string("(sys:load \"") + string_value(pair_cadr(Args)) + '"');
    return Scheme->T;
}
