#!/usr/bin/env python3

import sys
import re
import json
import requests
import os

RED = "\\x1b[31m"
GREEN = "\\x1b[32m"
YELLOW = "\\x1b[33m"
BLUE = "\\x1b[34m"
RESET = "\\x1b[0m"

def bitcast(type, value):
    return f"*({type}*)&{value}"

def get_fmtspec(decl):
    type = " ".join(decl.split()[:-1])
    ptr = '*' in decl
    char = 'char' in decl
    const = 'const' in decl
    void = 'void' in decl
    size_t = 'size_t' in decl
    long = 'long' in decl
    long_long = 'long long' in decl
    unsigned = 'unsigned' in decl
    int = 'int' in decl or 'signed' in decl or long or unsigned
    struct = 'struct' in decl
    _ = const
    # if char and ptr:
    #     return ("const char *", '\\"%10.s\\"')
    if void or ptr or struct:
        return ("void*", f"{BLUE}%p{RESET}")
    if size_t:
        return ("size_t", "%zu")
    if int:
        fmt = "%"
        if long:
            fmt += "l"
        if long_long:
            fmt += "ll"
        if unsigned:
            fmt += "u"
        else:
            fmt += "d"
        return (type, fmt)
    return ("void*", f"{BLUE}%p{RESET}")

if len(sys.argv) < 3:
    print(f"usage: {sys.argv[0]} <url> <output>")
    exit(1)

url = sys.argv[1]
outfname = sys.argv[2]

print(f"Fetching syscall table from {url}")
data = requests.get(url)
data = json.loads(data.text)

hdrguard = outfname.upper().replace('.', '_')

print(f"Creating {outfname}")
with open(outfname, "w") as outf:
    outf.write(f" /* Generated with {os.path.basename(__file__)} from {url} */\n")
    outf.write(f"#ifndef {hdrguard}\n")
    outf.write(f"#define {hdrguard}\n")
    outf.write("\n")
    outf.write("#include <linux/ptrace.h>\n")
    outf.write("#include <stdio.h>\n")
    outf.write("#include <assert.h>\n")
    outf.write("\n")
    outf.write("static inline void print_ptrace_syscall_info(struct ptrace_syscall_info *info)\n")
    outf.write("{\n")
    outf.write("\tswitch (info->op)\n")
    outf.write("\t{\n")
    outf.write("\t/* Ignore everything besides (...)_ENTRY for now */\n")
    outf.write("\tcase PTRACE_SYSCALL_INFO_SECCOMP:\n")
    outf.write("\tcase PTRACE_SYSCALL_INFO_NONE:\n")
    outf.write("\tcase PTRACE_SYSCALL_INFO_EXIT:\n")
    outf.write("\t\tbreak;\n")
    outf.write("\tcase PTRACE_SYSCALL_INFO_ENTRY:\n")
    outf.write("\t\tswitch (info->entry.nr)\n")
    outf.write("\t\t{\n")

    for syscall in data["syscalls"]:
        name = syscall["name"]
        nr = syscall["number"]
        sig = syscall["signature"]
        nargs = len(sig)
        outf.write(f'\t\tcase {nr}: printf("{YELLOW}{name}{RESET}(')
        for index, arg in enumerate(sig):
            _, fmt = get_fmtspec(arg)
            outf.write(fmt)
            if index < len(sig) - 1:
                outf.write(", ")
        outf.write(')\\n"')
        for index, arg in enumerate(sig):
            type, _ = get_fmtspec(arg)
            argstr = bitcast(type, f"info->entry.args[{index}]")
            outf.write(f", {argstr}")
        outf.write("); break;\n")

    outf.write('\t\tdefault: assert(0 && "invalid syscall number");\n')
    outf.write("\t\t}\n")
    outf.write("\t\tbreak;\n")
    outf.write('\tdefault: assert(0 && "invalid info.op value");\n')
    outf.write("\t}\n")
    outf.write("}\n")
    outf.write("\n")
    outf.write("#endif\n")
