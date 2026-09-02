#!/usr/bin/env python3
"""Report variables whose declared type does not match where their value came from.

Two type names can mean the same machine integer and still mean different
things to a person reading the code.  `fr_slen_t` is a `typedef` of `ssize_t`,
so the compiler sees no difference between them, but the two names carry
different promises about a negative return:

    fr_slen_t   a length, or minus the offset in the input where parsing failed
    ssize_t     a length, or -1, from the sbuff write and print functions

So a variable declared `fr_slen_t` and filled in from a function returning
`ssize_t` is a place where those two promises have been mixed up.  The value is
copied without complaint, and the code then treats -1 as "the error is at
offset 1".  `fr_filename_box_make_safe()` in `src/lib/util/file.c` is the
example that prompted this tool.

This reads the tree, records the type every function returns and the type of
every parameter it takes, records the declared type of every local variable,
and then reports each place where a value crosses from one type name to a
different one.  A value crosses in two ways:

    assignment          slen = fr_sbuff_in_escape(...)
    pointer argument    fr_sbuff_out_int32(&err, &num, ...)

The second form matters because the caller passes the address of a variable and
the function writes through the pointer, so the type has to agree there too.

Type names are compared **as written**.  Resolving `fr_slen_t` to `ssize_t`
first would hide every case the tool exists to find.  Names are resolved only
to work out how bad a mismatch is, which gives the four kinds reported:

    alias       the same machine type under a different name, as above.  The
                compiler cannot warn about these, so they are the ones worth
                reading first
    signedness  a signed value stored in an unsigned variable, or the reverse.
                A negative return becomes a very large positive number
    narrowing   a wide value stored in a narrow variable, so large values are
                silently cut short
    unrelated   the two types have nothing to do with each other

Widening, such as an `int` return stored in an `ssize_t`, is not reported: no
value is lost and no convention is crossed.

Parsing is done with regular expressions rather than a real C parser, because
the tree leans on macros heavily enough that a parser would need the whole
preprocessor to get through it.  So the tool can miss things, and can report a
mismatch that is not one.  Read the report as a list of places to look at, not
a list of proven faults.

usage:
    vartypes.py                             scan src/, report alias mismatches
    vartypes.py --kind all                  report every kind
    vartypes.py --kind signedness narrowing
    vartypes.py src/lib/util                scan one directory
    vartypes.py src/lib/util/file.c         scan one file
    vartypes.py --returns ssize_t           only values from ssize_t functions
    vartypes.py --declared fr_slen_t        only variables declared fr_slen_t
    vartypes.py --json                      machine readable output
    vartypes.py --self-test                 check the scanner against known answers
"""

import argparse
import json
import os
import re
import sys
import tempfile

#
#  Words which can appear in front of a type and tell us nothing about it.
#
NOISE = re.compile(r'\b(?:static|inline|extern|register|volatile|const|struct|union|enum|'
                   r'_Thread_local|__thread|_Atomic|'
                   r'UNUSED|CC_HINT|NDEBUG_LOCATION_ARGS|FR_[A-Z0-9_]+|_[A-Z][A-Z0-9_]*)\b')

#
#  Statement keywords.  A line starting with one of these is not a declaration.
#
KEYWORDS = frozenset("""
if else for while do switch case default return goto break continue sizeof
typedef fr_assert fr_cond_assert fr_fatal_assert MEM RDEBUG DEBUG ERROR WARN
""".split())

#
#  Integer types we understand well enough to grade a mismatch, as
#  (signedness, width in bits).  Anything absent is treated as "unrelated".
#
INT_TYPES = {
    "char":                 ("signed",   8),
    "signed char":          ("signed",   8),
    "unsigned char":        ("unsigned", 8),
    "int8_t":               ("signed",   8),
    "uint8_t":              ("unsigned", 8),
    "short":                ("signed",   16),
    "unsigned short":       ("unsigned", 16),
    "int16_t":              ("signed",   16),
    "uint16_t":             ("unsigned", 16),
    "int":                  ("signed",   32),
    "unsigned":             ("unsigned", 32),
    "unsigned int":         ("unsigned", 32),
    "int32_t":              ("signed",   32),
    "uint32_t":             ("unsigned", 32),
    "long":                 ("signed",   64),
    "unsigned long":        ("unsigned", 64),
    "long long":            ("signed",   64),
    "unsigned long long":   ("unsigned", 64),
    "int64_t":              ("signed",   64),
    "uint64_t":             ("unsigned", 64),
    "ssize_t":              ("signed",   64),
    "size_t":               ("unsigned", 64),
    "off_t":                ("signed",   64),
    "intptr_t":             ("signed",   64),
    "uintptr_t":            ("unsigned", 64),
    "time_t":               ("signed",   64),
    "bool":                 ("unsigned", 8),
}

#
#  The same integer type can be spelled several ways.  Fold each spelling onto
#  one name so that "long int" and "long" are not read as two different types.
#
CANON = {
    "signed":                   "int",
    "signed int":               "int",
    "short int":                "short",
    "signed short":             "short",
    "signed short int":         "short",
    "unsigned short int":       "unsigned short",
    "long int":                 "long",
    "signed long":              "long",
    "signed long int":          "long",
    "unsigned long int":        "unsigned long",
    "long long int":            "long long",
    "signed long long":         "long long",
    "unsigned long long int":   "unsigned long long",
    "unsigned":                 "unsigned int",
}

KINDS = ("alias", "signedness", "narrowing", "unrelated")


def tidy(text):
    """Collapse whitespace and drop the macros which decorate a declaration."""
    text = re.sub(r'CC_HINT\s*\((?:[^()]|\([^()]*\))*\)', ' ', text)
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    return " ".join(text.split())


def base_type(spelling):
    """The type name on its own: no qualifiers, no storage class, no pointers."""
    text = NOISE.sub(' ', spelling)
    text = text.replace('*', ' ')
    return " ".join(text.split())


def stars(spelling):
    """How many levels of pointer a type spelling has."""
    return spelling.count('*')


def submodules(path=".gitmodules"):
    """Every git submodule path.

    A submodule holds someone else's code, so a mismatch inside one is not ours
    to fix.  Reading .gitmodules keeps the list correct as submodules come and
    go, rather than naming directories here and going stale.
    """
    try:
        text = open(path, errors="replace").read()
    except OSError:
        return set()
    return {m.strip() for m in re.findall(r'(?m)^\s*path\s*=\s*(.+)$', text)}


def source_files(target):
    """Every C source and header file at or under a path."""
    if os.path.isfile(target):
        return [target]

    vendored = submodules()
    out = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs
                   if d not in ("__pycache__", "coverity-model")
                   and os.path.join(root, d).lstrip("./") not in vendored]
        for name in sorted(files):
            if name.endswith((".c", ".h")):
                out.append(os.path.join(root, name))
    return out


def collect_typedefs(paths):
    """Map each typedef name to the type it stands for, following chains."""
    direct = {}

    for path in paths:
        try:
            src = open(path, errors="replace").read()
        except OSError:
            continue

        #
        #  typedef ssize_t fr_slen_t;
        #
        for under, name in re.findall(
                r'(?m)^\s*typedef\s+((?:unsigned\s+|signed\s+|long\s+|short\s+|const\s+)*'
                r'[A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;', src):
            under = " ".join(under.split())
            if under != name:
                direct[name] = under

    #
    #  Follow each chain to the end, guarding against a loop.
    #
    resolved = {}
    for name in direct:
        seen, cur = {name}, direct[name]
        while cur in direct and cur not in seen:
            seen.add(cur)
            cur = direct[cur]
        resolved[name] = cur

    return resolved


def canon(name):
    """One spelling per integer type, so "long int" and "long" agree."""
    return CANON.get(name, name)


def resolve(spelling, typedefs):
    """The underlying type of a spelling, used only to grade a mismatch."""
    name = canon(base_type(spelling))
    seen = set()
    while name in typedefs and name not in seen:
        seen.add(name)
        name = canon(typedefs[name])
    return name


def collect_signatures(paths):
    """Map each function name to (return type, [parameter types], file, line)."""
    #
    #  A return type, a name, and a parameter list, ending in ';' or '{'.
    #
    decl = re.compile(
        r'(?m)^(?P<lead>(?:[A-Za-z_][A-Za-z0-9_]*\s+){0,4})'
        r'(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<params>[^;{]*?)\)\s*'
        r'(?:CC_HINT\s*\((?:[^()]|\([^()]*\))*\)\s*)*(?:;|\{)')

    out, local = {}, {}
    for path in paths:
        try:
            src = open(path, errors="replace").read()
        except OSError:
            continue

        #
        #  Splice continued lines so a parameter list spanning lines matches.
        #
        flat = re.sub(r'(?m)^\s*#.*$', '', src)
        flat = re.sub(r',\s*\n\s*', ', ', flat)

        for m in decl.finditer(flat):
            lead, name, params = m.group("lead"), m.group("name"), m.group("params")
            if name in KEYWORDS or not lead.strip():
                continue

            #
            #  The storage class is not part of the type, and printing it just
            #  makes the report harder to read.
            #
            rtype = tidy(re.sub(r'\b(?:static|inline|extern|_[A-Z][A-Z0-9_]*)\b', ' ', lead))
            if not rtype or base_type(rtype) in ("", "return"):
                continue


            #
            #  A pointer return leaves its '*' glued to the name.
            #
            trailing = flat[:m.start("name")]
            if trailing.rstrip().endswith('*'):
                rtype += " *"

            ptypes = []
            for arg in params.split(','):
                arg = tidy(arg)
                if not arg or arg == "void":
                    continue
                #
                #  Drop the parameter name, keep the type.
                #
                ptypes.append(re.sub(r'\b[A-Za-z_][A-Za-z0-9_]*\s*(\[[^\]]*\])?$', '', arg).strip()
                              or arg)

            line = flat[:m.start()].count("\n") + 1
            sig = (rtype, ptypes, path, line, "static" in lead.split())

            #
            #  A definition beats a prototype, and the first of either wins.
            #
            if name not in out or m.group(0).rstrip().endswith('{'):
                out[name] = sig

            #
            #  Keep a per file copy, so a "static" name resolves within the
            #  file that declares it rather than to another file's function of
            #  the same name.
            #
            key = (path, name)
            if key not in local or m.group(0).rstrip().endswith('{'):
                local[key] = sig

            #
            #  A header and its .c file are one unit for this purpose.
            #
            if path.endswith('.h'):
                local.setdefault((path[:-2] + '.c', name), sig)

    return out, local


def split_functions(path):
    """Break a file into its top level functions: (name, first line, body lines)."""
    try:
        lines = open(path, errors="replace").read().split("\n")
    except OSError:
        return []

    start = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*\(')
    out, i = [], 0

    while i < len(lines):
        line = lines[i]
        if start.match(line) and not line.startswith(('#', '/', '*', ' ', '\t', '}')) \
           and 'typedef' not in line and not line.rstrip().endswith(';'):
            signature, j, complete = line, i, True

            while j < len(lines) and not lines[j].rstrip().endswith('{'):
                j += 1
                if (j - i > 14) or (j >= len(lines)):
                    complete = False
                    break
                signature += " " + lines[j].strip()

            if complete and j < len(lines):
                k = j + 1
                while k < len(lines) and lines[k] != '}':
                    k += 1
                out.append((function_name(signature), i + 1, lines[i:k + 1]))
                i = k + 1
                continue
        i += 1

    return out


def function_name(signature):
    """The name out of a function signature, ignoring attribute macros."""
    text = tidy(signature.split('{')[0])
    text = re.sub(r'\b(static|inline|extern)\b', ' ', text)

    paren = text.find('(')
    if paren < 0:
        return "?"

    match = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*$', text[:paren])
    return match.group(1) if match else "?"


def split_args(text):
    """Split an argument list on the commas which separate arguments.

    A nested call brings its own commas, as in `f(&FR_DBUFF_TMP(p, end), &x)`.
    Splitting on every comma would count three arguments there instead of two,
    and every argument after the first would be matched against the wrong
    parameter.
    """
    args, depth, current = [], 0, ""

    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1

        if (ch == ',') and (depth == 0):
            args.append(current)
            current = ""
        else:
            current += ch

    args.append(current)
    return args


def whole_rhs(line, open_paren):
    """Is this call the entire right hand side of the assignment?

    `j = fr_fast_rand(&ctx) % len` gives `j` the type of the modulo, not the
    type the function returns, so the call has to stand alone to say anything
    about the variable.
    """
    depth, i = 0, open_paren
    while i < len(line):
        if line[i] == '(':
            depth += 1
        elif line[i] == ')':
            depth -= 1
            if depth == 0:
                break
        i += 1
    else:
        return False

    return re.match(r'\s*(?:;|,|\)|$)', line[i + 1:]) is not None


def calls_in(line):
    """Each complete function call on a line, as (name, [argument text])."""
    out = []

    for m in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', line):
        depth, i = 0, m.end() - 1

        while i < len(line):
            if line[i] == '(':
                depth += 1
            elif line[i] == ')':
                depth -= 1
                if depth == 0:
                    break
            i += 1

        #
        #  An unbalanced call carries on to the next line, so the argument
        #  list here is incomplete and cannot be matched to parameters.
        #
        if depth != 0:
            continue

        out.append((m.group(1), split_args(line[m.end():i])))

    return out


def local_declarations(body, first_line):
    """Map each local variable to every declaration of that name.

    One function can declare the same name more than once, in blocks which do
    not overlap:

        case A: { ssize_t slen; ... }
        case B: { fr_slen_t slen; ... }

    Keeping only the last would report the wrong type for every use in the
    earlier blocks, so each name maps to a list of (type, line) and a use picks
    the declaration nearest above it.
    """
    decl = re.compile(
        r'^[ \t]+(?P<type>(?:const\s+|volatile\s+|register\s+|static\s+|struct\s+|union\s+|enum\s+'
        r'|_Thread_local\s+|__thread\s+|_Atomic\s+)*'
        r'[A-Za-z_][A-Za-z0-9_]*(?:\s+(?:int|long|char|short))*)'
        r'(?P<rest>[ \t\*]+[A-Za-z_][A-Za-z0-9_]*[^;=]*?)\s*(?:=[^;]*)?;\s*(?:/[/*].*)?$')

    out = {}
    for offset, line in enumerate(body):
        #
        #  Anything with these in it is a statement, not a declaration.
        #
        if re.search(r'\b(?:return|goto|if|else|while|for|switch|case)\b', line):
            continue
        if '->' in line or '(' in line.split('=')[0]:
            continue

        m = decl.match(line)
        if not m:
            continue

        vtype = tidy(re.sub(r'\b(?:static|register|_Thread_local|__thread)\b', ' ',
                            m.group("type")))
        rest = m.group("rest")
        if base_type(vtype) in KEYWORDS or not base_type(vtype):
            continue

        #
        #  One declaration can name several variables.
        #
        for piece in rest.split(','):
            piece = piece.strip()
            name = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?$', piece)
            if not name:
                continue
            spelling = vtype + (" *" * piece.count('*'))
            out.setdefault(name.group(1), []).append((spelling, first_line + offset))

    return out


def declared_at(declarations, var, use_line):
    """The declaration of `var` in force at `use_line`: the nearest above."""
    seen = [d for d in declarations[var] if d[1] <= use_line]

    #
    #  A use above every declaration of the name means the declarations are in
    #  blocks this scanner cannot see into.  The first is the best guess.
    #
    return seen[-1] if seen else declarations[var][0]


def classify(target, source, typedefs):
    """How bad is storing a `source` value in a `target` variable?"""
    if tidy(target) == tidy(source):
        return None

    t_base, s_base = base_type(target), base_type(source)
    if t_base == s_base and stars(target) == stars(source):
        return None

    #
    #  A pointer on one side and not the other is not comparable as an integer.
    #
    if stars(target) or stars(source):
        return None if stars(target) == stars(source) else "unrelated"

    t_res, s_res = resolve(target, typedefs), resolve(source, typedefs)

    if t_res == s_res:
        #
        #  The same machine type wearing two names.  No compiler can warn.
        #
        return "alias"

    t_int, s_int = INT_TYPES.get(t_res), INT_TYPES.get(s_res)
    if not t_int or not s_int:
        return "unrelated"

    if t_int == s_int:
        return "alias"

    if t_int[0] != s_int[0]:
        return "signedness"

    if t_int[1] < s_int[1]:
        return "narrowing"

    #
    #  Widening loses nothing and crosses no convention.
    #
    return None


def scan_file(path, sigs, local, typedefs, args):
    """Every type mismatch in one file."""
    found = []

    def signature(name):
        """The signature for a name, preferring one declared in this file.

        A "static" function belongs to the file that declares it, so another
        file's function of the same name says nothing about this call.
        """
        here = local.get((path, name))
        if here:
            return here

        other = sigs.get(name)
        return None if (other and other[4]) else other

    for fname, first, body in split_functions(path):
        locals_ = local_declarations(body, first)
        if not locals_:
            continue

        names = "|".join(re.escape(n) for n in locals_)

        for offset, line in enumerate(body):
            lineno = first + offset

            #
            #  var = some_function(...)
            #
            for m in re.finditer(r'(?<![.>\w])(' + names + r')\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(', line):
                var, callee = m.group(1), m.group(2)

                #
                #  The lookbehind above rejects "x.len = f()" and "x->len =
                #  f()", which name a field rather than the local variable
                #  which happens to share the name.
                #
                if not whole_rhs(line, m.end() - 1):
                    continue
                sig = None if callee in KEYWORDS else signature(callee)
                if not sig:
                    continue

                vtype, vline = declared_at(locals_, var, lineno)
                rtype = sig[0]

                #
                #  A function returning void has no value to assign, so a
                #  match here is a misread signature, or a name which belongs
                #  to some other file.
                #
                if base_type(rtype) == "void" and not stars(rtype):
                    continue

                kind = classify(vtype, rtype, typedefs)
                if kind:
                    found.append(dict(file=path, function=fname, kind=kind, how="assignment",
                                      var=var, declared=vtype, decl_line=vline,
                                      callee=callee, other=rtype, use_line=lineno,
                                      text=line.strip()))

            #
            #  some_function(..., &var, ...)
            #
            for callee, arglist in calls_in(line):
                sig = None if callee in KEYWORDS else signature(callee)
                if not sig:
                    continue

                ptypes = sig[1]
                for pos, arg in enumerate(arglist):
                    hit = re.match(r'\s*&\s*([A-Za-z_][A-Za-z0-9_]*)\s*$', arg)
                    if not hit or hit.group(1) not in locals_:
                        continue
                    if pos >= len(ptypes):
                        continue

                    var = hit.group(1)
                    vtype, vline = declared_at(locals_, var, lineno)
                    ptype = ptypes[pos]
                    if not stars(ptype):
                        continue

                    #
                    #  The parameter is a pointer to the variable's type, so
                    #  compare one level of pointer less.
                    #
                    pointee = re.sub(r'\*\s*$', '', ptype).strip()

                    #
                    #  A void pointer parameter takes the address of anything,
                    #  so there is no mismatch to report.
                    #
                    if base_type(pointee) == "void":
                        continue

                    kind = classify(vtype, pointee, typedefs)
                    if kind:
                        found.append(dict(file=path, function=fname, kind=kind,
                                          how="pointer argument %d" % (pos + 1),
                                          var=var, declared=vtype, decl_line=vline,
                                          callee=callee, other=pointee, use_line=lineno,
                                          text=line.strip()))

    #
    #  Filters the caller asked for.
    #
    out = []
    for f in found:
        if f["kind"] not in args.kind:
            continue
        if args.returns and base_type(f["other"]) not in args.returns:
            continue
        if args.declared and base_type(f["declared"]) not in args.declared:
            continue
        out.append(f)

    return out


def report(found):
    """Print the mismatches, grouped by kind and then by file."""
    if not found:
        print("No type mismatches found.")
        return

    blurb = {
        "alias":      "Same machine type, different name.  The compiler cannot warn about these.",
        "signedness": "Signed and unsigned mixed.  A negative value becomes a large positive one.",
        "narrowing":  "A wide value stored in a narrow variable.  Large values are cut short.",
        "unrelated":  "The two types are not related.",
    }

    for kind in KINDS:
        rows = [f for f in found if f["kind"] == kind]
        if not rows:
            continue

        print("\n## %s (%d)\n" % (kind, len(rows)))
        print(blurb[kind])

        last = None
        for f in sorted(rows, key=lambda r: (r["file"], r["use_line"])):
            if f["file"] != last:
                print("\n### %s\n" % f["file"])
                last = f["file"]

            if f["how"] == "assignment":
                came_from = "%s() returns %s" % (f["callee"], f["other"])
            else:
                came_from = "%s() writes %s through %s" % (f["callee"], f["other"], f["how"])

            print("%s()" % f["function"])
            print("    %s:%d: %s %s" % (f["file"], f["decl_line"], f["declared"], f["var"]))
            print("    %s:%d: %s" % (f["file"], f["use_line"], came_from))
            print("        %s" % f["text"])
            print()

    print("\n%d mismatches in %d files." % (found.__len__(), len({f["file"] for f in found})))


#
#  A small program with a known set of mismatches in it, used by --self-test.
#
#  The fixture stands on its own.  The types and signatures come from the
#  fixture and from nowhere else, so a failure is a fault in this script rather
#  than a change somewhere in the tree.
#
SELF_TEST_SOURCE = """typedef ssize_t fr_slen_t;

static fr_slen_t give_slen(int a);
static ssize_t   give_ssize(int a);
static int       give_int(int a);
static void      take_int32(int32_t *out);
static void      take_size(size_t *out);
static void      take_slen(fr_slen_t *out);
static void      take_two(int a, ssize_t *out);
static int       pick(int a, int b);
static ssize_t   give_ssize_expr(int a);
static fr_slen_t give_slen_field(int a);

typedef struct { ssize_t b; } holder_t;

int probe(void)
{
\tfr_slen_t\ta;
\tssize_t\t\tb;
\tsize_t\t\tc;
\tint\t\td;
\tint32_t\t\te;
\tholder_t\tst;

\ta = give_ssize(1);
\tb = give_slen(1);
\tc = give_ssize(1);
\td = give_ssize(1);
\te = give_int(1);
\tb = give_ssize(1);

\ttake_int32(&d);
\ttake_size(&b);
\ttake_slen(&b);
\ttake_two(pick(1, 2), &c);
\ttake_slen(&a);

\ta = give_ssize_expr(1) % 7;
\tst.b = give_slen_field(1);

\treturn a + b + c + d + e + st.b;
}
"""

#
#  Every mismatch the fixture contains, as (variable, function, kind, how).
#
#  The two lines the fixture ends with, "b = give_ssize(1)" and
#  "take_slen(&a)", hand a value to a variable of its own type, so neither may
#  appear.  The check is for an exact match, which covers both.
#
SELF_TEST_EXPECTED = {
    ("a", "give_ssize", "alias",      "assignment"),
    ("b", "give_slen",  "alias",      "assignment"),
    ("c", "give_ssize", "signedness", "assignment"),
    ("d", "give_ssize", "narrowing",  "assignment"),
    ("e", "give_int",   "alias",      "assignment"),
    ("d", "take_int32", "alias",      "pointer argument 1"),
    ("b", "take_size",  "signedness", "pointer argument 1"),
    ("b", "take_slen",  "alias",      "pointer argument 1"),
    ("c", "take_two",   "signedness", "pointer argument 2"),
}


def self_test():
    """Run the scanner over the fixture and compare against the known answers.

    Returns the number of differences, so zero means the scanner works.
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "vartypes_fixture.c")
        with open(path, "w") as fd:
            fd.write(SELF_TEST_SOURCE)

        typedefs = collect_typedefs([path])
        sigs, local = collect_signatures([path])

        every = argparse.Namespace(kind=list(KINDS), returns=None, declared=None)
        found = scan_file(path, sigs, local, typedefs, every)

    got = {(f["var"], f["callee"], f["kind"], f["how"]) for f in found}

    missing = SELF_TEST_EXPECTED - got
    extra = got - SELF_TEST_EXPECTED

    for var, callee, kind, how in sorted(SELF_TEST_EXPECTED & got):
        print("  ok       %s from %s(), %s via %s" % (var, callee, kind, how))

    for var, callee, kind, how in sorted(missing):
        print("  MISSING  %s from %s(), expected %s via %s" % (var, callee, kind, how))

    for var, callee, kind, how in sorted(extra):
        print("  EXTRA    %s from %s(), reported %s via %s" % (var, callee, kind, how))

    print()
    if missing or extra:
        print("self test FAILED: %d missing, %d unexpected." % (len(missing), len(extra)))
    else:
        print("self test passed: %d of %d found, nothing unexpected."
              % (len(got), len(SELF_TEST_EXPECTED)))

    return len(missing) + len(extra)


def main():
    parser = argparse.ArgumentParser(
        description="Report variables whose declared type does not match where their value came from.")
    parser.add_argument("target", nargs="*", default=["src"],
                        help="files or directories to scan (default: src)")
    parser.add_argument("--kind", nargs="+", default=["alias"], choices=list(KINDS) + ["all"],
                        help="which mismatches to report (default: alias)")
    parser.add_argument("--returns", nargs="+", metavar="TYPE",
                        help="only values coming from these types")
    parser.add_argument("--declared", nargs="+", metavar="TYPE",
                        help="only variables declared with these types")
    parser.add_argument("--json", action="store_true", help="machine readable output")
    parser.add_argument("--self-test", action="store_true",
                        help="check the scanner against a fixture with known answers")
    parser.add_argument("--quiet", action="store_true", help="do not report progress")
    args = parser.parse_args()

    #
    #  The self test does not read the tree, so run it before anything else.
    #
    if args.self_test:
        sys.exit(1 if self_test() else 0)

    if "all" in args.kind:
        args.kind = list(KINDS)

    #
    #  Signatures and typedefs have to come from the whole tree, even when the
    #  report covers one file, because that one file calls into the rest.
    #
    tree = source_files("src") if os.path.isdir("src") else []
    for target in args.target:
        if not os.path.exists(target):
            sys.exit("%s: no such file or directory" % target)
        tree += [p for p in source_files(target) if p not in tree]

    if not args.quiet:
        print("Reading %d files for types and signatures..." % len(tree), file=sys.stderr)

    typedefs = collect_typedefs(tree)
    sigs, local = collect_signatures(tree)

    if not args.quiet:
        print("%d typedefs, %d functions." % (len(typedefs), len(sigs)), file=sys.stderr)

    wanted = []
    for target in args.target:
        wanted += [p for p in source_files(target) if p.endswith(".c") and p not in wanted]

    found = []
    for path in wanted:
        found += scan_file(path, sigs, local, typedefs, args)

    if args.json:
        json.dump(found, sys.stdout, indent=2)
        print()
    else:
        report(found)


if __name__ == "__main__":
    main()
