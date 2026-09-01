#!/usr/bin/env python3
"""Report how C structures are laid out in memory, and how to lay them out better.

A field has to start at an address the machine can use for its type: an
eight byte pointer at a multiple of eight, a four byte integer at a
multiple of four, and so on.  When a small field sits in front of a large
one the compiler inserts padding to make that true, and that padding is
memory the structure pays for and cannot use.  Ordering the fields largest
first usually removes most of it.

This reads structure definitions out of one or more header files, works out
where every field lands under the usual sixty four bit rules, and reports
the padding.  With --reorder it also prints the order that would be
smallest, and by how much.

Parsing is done with pycparser.  Header files are not run through a real C
preprocessor, so #include is ignored; give the tool every header it needs
on the command line, and use -D for the build flags that matter.

usage:
    alignment.py header.h
    alignment.py header.h --reorder
    alignment.py alloc_priv.h dlist.h -D FR_ALLOC_DEBUG --struct fr_alloc_ctx_s
"""

import argparse
import re
import sys

try:
    from pycparser import c_ast, c_parser
except ImportError:
    sys.exit("alignment.py needs pycparser: pip install pycparser")


#
#  Sizes and alignments.  LP64 is Linux and macOS; LLP64 is Windows, where
#  "long" is four bytes rather than eight.
#
LP64 = {
    "void": (1, 1),
    "_Bool": (1, 1), "bool": (1, 1),
    "char": (1, 1),
    "short": (2, 2),
    "int": (4, 4),
    "long": (8, 8),
    "long long": (8, 8),
    "float": (4, 4),
    "double": (8, 8),
    "long double": (16, 16),

    "int8_t": (1, 1), "uint8_t": (1, 1),
    "int16_t": (2, 2), "uint16_t": (2, 2),
    "int32_t": (4, 4), "uint32_t": (4, 4),
    "int64_t": (8, 8), "uint64_t": (8, 8),
    "size_t": (8, 8), "ssize_t": (8, 8), "ptrdiff_t": (8, 8),
    "intptr_t": (8, 8), "uintptr_t": (8, 8),
    "intmax_t": (8, 8), "uintmax_t": (8, 8),
    "time_t": (8, 8), "off_t": (8, 8), "pid_t": (4, 4),
    "wchar_t": (4, 4), "char16_t": (2, 2), "char32_t": (4, 4),
    "float _Complex": (8, 4), "double _Complex": (16, 8),
}

LLP64 = dict(LP64)
LLP64.update({"long": (4, 4), "long double": (8, 8)})

POINTER = (8, 8)

#  Words which only qualify a base type and do not change its size.
NOISE = {"signed", "unsigned", "const", "volatile", "restrict", "_Atomic"}


class Layout:
    """A laid out structure or union."""

    def __init__(self, kind, name):
        self.kind = kind
        self.name = name
        self.fields = []            #  list of Field
        self.size = 0
        self.align = 1
        self.padding = 0            #  bytes lost to padding, including the tail
        self.forced_align = None
        self.packed = False


class Field:
    def __init__(self, name, type_name, size, align, bits=None):
        self.name = name
        self.type_name = type_name
        self.size = size            #  bytes, or None for a bitfield
        self.align = align
        self.bits = bits            #  width in bits, or None
        self.offset = 0             #  byte offset
        self.bit_offset = None      #  bit offset within its storage, bitfields only
        self.pad_before = 0


def die(msg):
    sys.exit("alignment.py: " + msg)


#
#  ======================================================================
#  Getting the source into a state pycparser will accept.
#  ======================================================================
#

def strip_comments(text):
    """Remove comments, keeping the line structure.

    pycparser expects preprocessed input and does not do this itself.
    Newlines inside a comment are kept so that the conditional handling
    below still sees the right lines.
    """
    out = []
    i, n = 0, len(text)

    while i < n:
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                break
            out.append("\n" * text.count("\n", i, end))
            i = end + 2
        elif text.startswith("//", i):
            end = text.find("\n", i)
            if end < 0:
                break
            i = end
        elif text[i] in "\"'":
            quote = text[i]
            out.append(text[i])
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\" and (i + 1) < n:
                    out.append(text[i])
                    i += 1
                out.append(text[i])
                i += 1
            if i < n:
                out.append(text[i])
                i += 1
        else:
            out.append(text[i])
            i += 1

    return "".join(out)


def resolve_conditionals(text, defines):
    """Handle #ifdef, #ifndef, #if defined, #else and #endif.

    Not a C preprocessor.  It exists so that a header whose fields depend
    on a build flag can be reported for the build you care about.  Every
    other directive is dropped, #include included, which is why the
    headers a structure depends on have to be named on the command line.
    """
    out = []
    stack = []                      #  (taking this branch, any branch taken yet)

    for line in text.split("\n"):
        bare = line.strip()
        outer = all(s[0] for s in stack)

        m = re.match(r"#\s*(ifdef|ifndef)\s+(\w+)", bare)
        if m:
            hit = m.group(2) in defines
            want = hit if m.group(1) == "ifdef" else not hit
            stack.append((want and outer, want))
            out.append("")
            continue

        m = re.match(r"#\s*if\s+(.+)", bare)
        if m:
            want = evaluate_if(m.group(1).strip(), defines)
            stack.append((want and outer, want))
            out.append("")
            continue

        if re.match(r"#\s*elif\b", bare):
            if stack:
                _, taken = stack[-1]
                up = all(s[0] for s in stack[:-1])
                want = (not taken) and evaluate_if(bare.split(None, 1)[1], defines)
                stack[-1] = (want and up, taken or want)
            out.append("")
            continue

        if re.match(r"#\s*else\b", bare):
            if stack:
                _, taken = stack[-1]
                up = all(s[0] for s in stack[:-1])
                stack[-1] = ((not taken) and up, True)
            out.append("")
            continue

        if re.match(r"#\s*endif\b", bare):
            if stack:
                stack.pop()
            out.append("")
            continue

        if bare.startswith("#"):
            out.append("")
            continue

        out.append(line if all(s[0] for s in stack) else "")

    return "\n".join(out)


def evaluate_if(expr, defines):
    """Evaluate the handful of #if forms that turn up in headers.

    Anything more involved is treated as true, which keeps the fields
    visible.  Dropping them silently would be worse: the report would be
    wrong and would not say so.
    """
    expr = expr.strip()
    if expr in ("0", "0L"):
        return False
    if expr in ("1", "1L"):
        return True

    m = re.fullmatch(r"(!?)\s*defined\s*\(?\s*(\w+)\s*\)?", expr)
    if m:
        hit = m.group(2) in defines
        return (not hit) if m.group(1) else hit

    return True


#  The start of an attribute.  The argument list is found by counting
#  parentheses rather than by matching them with a regular expression:
#  __attribute__((aligned(16))) nests three deep, and a pattern which
#  handles a fixed depth silently mangles anything deeper.
ATTR_HEAD = re.compile(r"\b(?:__attribute__|__attribute|CC_HINT|DIAG_OFF|DIAG_ON)\s*\(")


def attribute_spans(text):
    """Find every attribute, as (start, end, argument text)."""
    spans = []

    for m in ATTR_HEAD.finditer(text):
        depth = 0
        i = m.end() - 1                     #  sitting on the first "("
        while i < len(text):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    spans.append((m.start(), i + 1, text[m.end() - 1:i + 1]))
                    break
            i += 1

    return spans


def strip_attributes(text):
    """Blank out every attribute, keeping the line structure."""
    out = []
    last = 0

    for start, end, _ in attribute_spans(text):
        if start < last:
            continue                        #  nested inside one already removed
        out.append(text[last:start])
        out.append("\n" * text.count("\n", start, end))
        last = end

    out.append(text[last:])
    return "".join(out)


def find_attributes(body, defines):
    """Read "packed" and "aligned(n)" out of an attribute's argument text."""
    packed = bool(re.search(r"\bpacked\b", body))
    aligned = None

    m = re.search(r"\baligned\s*\(\s*([^()]*?)\s*\)", body)
    if m:
        arg = m.group(1).strip()
        if arg.isdigit():
            aligned = int(arg)
        elif arg in defines and str(defines[arg]).strip().isdigit():
            aligned = int(defines[arg])
        else:
            aligned = arg                   #  a name we were not told the value of

    return packed, aligned


SYNTHETIC = set()

#
#  C23 lets an enum name the type it is stored in: "enum : int8_t { ... }"
#  is one byte, not four.  pycparser does not know the syntax, so the base
#  type is taken off the text here and put back when the enum is measured.
#  Keyed by tag, with a synthetic tag invented for an anonymous enum.
#
ENUM_BASE = {}


def matching_open(text, close_index):
    """Index of the brace which the brace at close_index closes."""
    depth = 0
    i = close_index
    while i >= 0:
        if text[i] == "}":
            depth += 1
        elif text[i] == "{":
            depth -= 1
            if depth == 0:
                return i
        i -= 1
    return None


def tag_enum_base(text):
    """Rewrite "enum tag : type {" as "enum tag {", remembering the type."""
    out = []
    last = 0
    counter = 0

    pattern = re.compile(
        r"\benum\b\s*(\w+)?\s*:\s*"
        r"((?:unsigned|signed|char|short|int|long|_Bool|\w+)"
        r"(?:\s+(?:unsigned|signed|char|short|int|long))*)\s*(?=\{)")

    for m in pattern.finditer(text):
        tag = m.group(1)
        if not tag:
            counter += 1
            tag = "__anon_enum_%d" % counter
            SYNTHETIC.add(tag)
        ENUM_BASE[tag] = m.group(2).strip()

        out.append(text[last:m.start()])
        out.append("enum %s " % tag)
        last = m.end()

    out.append(text[last:])
    return "".join(out)


def tag_records(text, defines):
    """Note the attributes on each record, tagging anonymous ones.

    pycparser discards attributes, and "packed" and "aligned" both change
    the layout, so they are read off the text first.  Matching them back to
    the parsed node needs a name, and an anonymous struct has none, so this
    gives it one.  The tag is remembered as synthetic so the report can
    still call it anonymous.
    """
    attrs = {}
    spans = attribute_spans(text)
    found = []

    for close in re.finditer(r"\}", text):
        #  Attributes which follow this brace, with only space between.
        here = close.end()
        body = ""
        for start, end, arg in spans:
            if start < here:
                continue
            if text[here:start].strip():
                break
            body += arg
            here = end
        if not body:
            continue

        packed, aligned = find_attributes(body, defines)
        if not packed and aligned is None:
            continue

        open_index = matching_open(text, close.start())
        if open_index is None:
            continue

        head = re.search(r"\b(struct|union)\s+(\w+)?\s*$", text[:open_index])
        if not head:
            continue

        found.append((open_index, head, packed, aligned))

    #  Applied back to front, so that inserting a tag does not move the
    #  positions of the ones still to be done.
    counter = 0
    for open_index, head, packed, aligned in sorted(found, key=lambda f: -f[0]):
        kind, tag = head.group(1), head.group(2)

        if not tag:
            counter += 1
            tag = "__anon_%d" % counter
            SYNTHETIC.add(tag)
            at = head.end(1)
            text = text[:at] + " " + tag + text[at:]

        attrs[kind + " " + tag] = (packed, aligned)
        attrs[tag] = (packed, aligned)

    return text, attrs


def strip_directives(text):
    """Blank out #define and friends, keeping the line count.

    A macro body is not C, and one holding a for loop puts semicolons at
    file scope, which splits the declaration after it in the wrong place.
    #if and #ifdef have already been resolved by the time this runs.
    """
    lines = text.split("\n")
    out = []
    continued = False

    for line in lines:
        if continued or re.match(r"[ \t]*#[ \t]*"
                                 r"(define|undef|include|include_next|pragma|"
                                 r"error|warning|line|ident|sccs)\b", line):
            continued = line.rstrip().endswith("\\")
            out.append("")
            continue
        out.append(line)

    return "\n".join(out)


def extract_types(text):
    """Keep the type declarations and throw away everything else.

    Only typedefs and struct, union and enum definitions say anything about
    layout.  Function prototypes and inline function bodies say nothing,
    and each one is another chance for the parser to trip over a type it
    was never given.  Dropping them is what makes this work on real headers
    rather than only on tidy ones.
    """
    kept = []
    i, n = 0, len(text)
    start = 0
    depth = 0
    function_body = False

    while i < n:
        ch = text[i]

        if ch == "{":
            if depth == 0:
                #  A function body's brace follows the closing parenthesis of
                #  its argument list.  A struct, union or enum body's does
                #  not.  That is the difference to look at, and what follows
                #  the closing brace is not: "} name;" ends a typedef but
                #  reads like the start of the next declaration.
                function_body = text[start:i].rstrip().endswith(")")
            depth += 1

        elif ch == "}":
            depth -= 1
            if depth == 0 and function_body:
                chunk = text[start:i + 1]
                kept.append("\n" * chunk.count("\n"))
                start = i + 1

        elif ch == ";" and depth == 0:
            chunk = text[start:i + 1]
            if is_type_declaration(chunk):
                kept.append(chunk)
            kept.append("\n" * chunk.count("\n"))
            start = i + 1

        i += 1

    return "".join(kept)


def is_type_declaration(chunk):
    """Does this top level chunk define a type?"""
    head = chunk.strip()
    if not head:
        return False
    if head.startswith("typedef"):
        return True
    #  "struct foo { ... };" defines one.  "struct foo *bar(void);" does not.
    return bool(re.match(r"^(?:struct|union|enum)\b", head)) and "{" in head


def sanitise(text, defines, macros=None, plain=None):
    """Return source pycparser can parse, and the attributes found in it."""
    #
    #  Directives go first, before the comments.  A macro is continued by
    #  a backslash at the end of the line, and removing a comment from the
    #  middle of one leaves a line which does not end in a backslash, so
    #  the rest of the macro body would be read as C.
    #
    text = strip_directives(text)
    #
    #  A line splice outside a macro is legal and does nothing, and
    #  src/lib/util/slab.h has one left over on a plain typedef.  The
    #  backslash goes; the line break stays, so line numbers still match.
    #
    text = re.sub(r"\\[ \t]*$", "", text, flags=re.M)
    text = strip_comments(text)
    text = resolve_conditionals(text, defines)
    if macros or plain:
        text = expand_macros(text, macros or {}, plain)
    text = tag_enum_base(text)
    text, attrs = tag_records(text, defines)

    text = strip_attributes(text)
    #  Compiler extensions which carry no layout meaning.
    text = re.sub(r"\b__extension__\b", "", text)
    #
    #  C11 atomics.  "_Atomic(int) x" and "_Atomic int x" are laid out the
    #  same as the type inside, so the spelling can go.
    #
    text = re.sub(r"\b_Atomic\s*\(([^()]*)\)", r"\1", text)
    text = re.sub(r"\b_Atomic\b", "", text)
    #
    #  FreeRADIUS headers write "_CONST" where a field is const to callers
    #  and writable inside the library.  It is "const" or nothing, and
    #  neither spelling changes where a field sits.
    #
    text = re.sub(r"\b_CONST\b", "", text)
    #
    #  UNUSED is __attribute__((unused)).  It says nothing about layout,
    #  and dict.h writes it inside a function pointer typedef, where the
    #  attribute stripper does not reach.
    #
    text = re.sub(r"\bUNUSED\b", "", text)
    text = re.sub(r"\b(?:__restrict__|__restrict|restrict)\b", "", text)
    text = re.sub(r"\b(?:__inline__|__inline)\b", "inline", text)
    text = re.sub(r"\b(?:__signed__|__signed)\b", "signed", text)
    text = re.sub(r"\b(?:__const__|__const)\b", "const", text)
    text = re.sub(r"\b(?:__volatile__|__volatile)\b", "volatile", text)
    text = re.sub(r"\basm\s*\([^)]*\)", "", text)
    text = re.sub(r"\b__asm__?\s*(?:volatile\s*)?\([^)]*\)", "", text)
    #  RCSID("...") and friends sit at file scope and are not declarations.
    text = re.sub(r"\bRCSIDH?\s*\([^)]*\)", "", text)

    return extract_types(text), attrs


#
#  ======================================================================
#  Working out how big a type is.
#  ======================================================================
#

#
#  The limits from <stdint.h>, which array dimensions are often written
#  in terms of.  A -D on the command line overrides any of them.
#
STANDARD_CONSTS = {
    "CHAR_BIT": 8,
    "INT8_MIN": -128, "INT8_MAX": 127, "UINT8_MAX": 255,
    "INT16_MIN": -32768, "INT16_MAX": 32767, "UINT16_MAX": 65535,
    "INT32_MIN": -2147483648, "INT32_MAX": 2147483647,
    "UINT32_MAX": 4294967295,
    "INT64_MIN": -9223372036854775808, "INT64_MAX": 9223372036854775807,
    "UINT64_MAX": 18446744073709551615,
    "SCHAR_MIN": -128, "SCHAR_MAX": 127, "UCHAR_MAX": 255,
    "SHRT_MIN": -32768, "SHRT_MAX": 32767, "USHRT_MAX": 65535,
    "INT_MIN": -2147483648, "INT_MAX": 2147483647, "UINT_MAX": 4294967295,
}


def expression_text(node):
    """A short spelling of an expression, for a diagnostic."""
    if isinstance(node, c_ast.Constant):
        return str(node.value)
    if isinstance(node, c_ast.ID):
        return node.name
    if isinstance(node, c_ast.UnaryOp):
        return "%s%s" % (node.op, expression_text(node.expr))
    if isinstance(node, c_ast.BinaryOp):
        return "%s %s %s" % (expression_text(node.left), node.op,
                             expression_text(node.right))
    if isinstance(node, c_ast.FuncCall):
        args = []
        if node.args is not None:
            args = [expression_text(a) for a in node.args.exprs]
        return "%s(%s)" % (expression_text(node.name), ", ".join(args))
    if isinstance(node, c_ast.Typename):
        #
        #  The first argument of offsetof() parses as a type, not an
        #  expression.  Spell it the way the header wrote it, so it can be
        #  matched against what struct_sizes printed.
        #
        inner = node.type
        while hasattr(inner, "type") and not isinstance(inner, c_ast.IdentifierType):
            inner = inner.type
        if isinstance(inner, c_ast.IdentifierType):
            return " ".join(inner.names)
        return "a type"
    return node.__class__.__name__


class Types:
    """Everything known about the sizes of types in the files given."""

    def __init__(self, model, overrides, attrs, opaque=None, consts=None):
        self.base = dict(model)
        self.base.update(overrides)
        #
        #  Types which are incomplete here: TALLOC_CTX is void, DIR and
        #  fr_hash_table_t are forward declared structs.  They have no size
        #  and only ever appear behind a pointer.  Naming them lets the
        #  headers parse; measuring one by value is an error, not a guess.
        #
        self.opaque = set(opaque or ())
        #
        #  Named constants from -D, for array dimensions written as
        #  "uint8_t part_adv[UINT8_MAX + 1]".
        #
        self.consts = {k: str(v) for k, v in STANDARD_CONSTS.items()}
        self.consts.update(consts or {})
        self.attrs = attrs
        self.typedefs = {}          #  name -> AST type node
        self.records = {}           #  "struct foo" / "union foo" -> AST node
        self.unknown = set()
        self.laid_out = {}          #  cache, keyed by id() of the AST node

    def learn(self, ast):
        """Record every typedef and every tagged struct or union."""
        class Walker(c_ast.NodeVisitor):
            def visit_Typedef(_, node):
                self.typedefs[node.name] = node.type
                _.generic_visit(node)

            def visit_Struct(_, node):
                if node.name and node.decls is not None:
                    self.records["struct " + node.name] = node
                _.generic_visit(node)

            def visit_Union(_, node):
                if node.name and node.decls is not None:
                    self.records["union " + node.name] = node
                _.generic_visit(node)

            def visit_Enum(_, node):
                #
                #  Enumerators are named constants, and dict.h sizes an
                #  array with the last one: uint8_t ext[FR_DICT_ATTR_EXT_MAX].
                #  A value carries on from the one before it when it is not
                #  written out.
                #
                if node.values is not None:
                    running = 0
                    for item in node.values.enumerators:
                        if item.value is not None:
                            given = self.const_value(item.value)
                            if given is None:
                                #  An enumerator this tool cannot follow
                                #  makes every later one a guess.
                                break
                            running = given
                        #  A -D on the command line still wins.
                        self.consts.setdefault(item.name, str(running))
                        running += 1
                _.generic_visit(node)

        Walker().visit(ast)

    def name_of(self, node):
        """A readable spelling of a type, for the report."""
        if isinstance(node, c_ast.PtrDecl):
            inner = self.name_of(node.type).rstrip()

            #
            #  A pointer to a pointer is spelled "char **", not "char * *".
            #
            return inner + "*" if inner.endswith("*") else inner + " *"
        if isinstance(node, c_ast.ArrayDecl):
            dim = self.array_len(node)
            return "%s[%s]" % (self.name_of(node.type), dim if dim is not None else "")
        if isinstance(node, c_ast.FuncDecl):
            return "function"
        if isinstance(node, c_ast.TypeDecl):
            quals = " ".join(node.quals) + " " if node.quals else ""
            return quals + self.name_of(node.type)
        if isinstance(node, c_ast.IdentifierType):
            return " ".join(node.names)
        if isinstance(node, c_ast.Struct):
            name = node.name
            return "struct " + ("(anonymous)" if (not name or name in SYNTHETIC) else name)
        if isinstance(node, c_ast.Union):
            name = node.name
            return "union " + ("(anonymous)" if (not name or name in SYNTHETIC) else name)
        if isinstance(node, c_ast.Enum):
            return "enum " + (node.name or "(anonymous)")
        return "?"

    def const_text(self, name, depth=0):
        """The value of a named constant, following one name to another.

        A #define body may be arithmetic over other names, as in
        "#define SBUFF_CHAR_CLASS UINT8_MAX + 1", so names are substituted
        until only numbers and operators are left.
        """
        if depth > 8:
            return None

        body = self.consts.get(name)
        if body is None:
            return None

        text = str(body).strip()

        #  Substitute every name in the body for its own value.
        for word in set(re.findall(r"[A-Za-z_]\w*", text)):
            if word == name:
                return None
            value = self.const_text(word, depth + 1)
            if value is None:
                return None
            text = re.sub(r"\b%s\b" % re.escape(word), str(value), text)

        #  What is left must be arithmetic over integers.  C divides
        #  integers towards zero; Python's // is close enough for a
        #  dimension, which is never negative.
        text = re.sub(r"\b(\d+)[uUlL]+\b", r"\1", text)
        if not re.fullmatch(r"[\d\s+\-*/()<>]+", text):
            return None
        text = text.replace("/", "//").replace("////", "//")

        try:
            value = eval(text, {"__builtins__": {}}, {})
        except Exception:
            return None

        return value if isinstance(value, int) else None

    def const_value(self, node):
        """The value of a constant expression, or None if it is not one."""
        if isinstance(node, c_ast.Constant):
            try:
                #  Strip a C integer suffix: 1024UL is 1024.
                return int(str(node.value).rstrip("uUlL"), 0)
            except ValueError:
                return None

        if isinstance(node, c_ast.ID):
            return self.const_text(node.name)

        if isinstance(node, c_ast.FuncCall):
            #
            #  "uint8_t pad[offsetof(fr_value_box_t, safe_for)]" needs the
            #  offset of a field in a structure this tool only knows the
            #  size of.  struct_sizes prints those under the same spelling.
            #
            text = expression_text(node)
            if text in self.base:
                return self.base[text][0]
            return None

        if isinstance(node, c_ast.UnaryOp):
            inner = self.const_value(node.expr)
            if inner is None:
                return None
            if node.op == "-":
                return -inner
            if node.op == "+":
                return inner
            if node.op == "~":
                return ~inner
            return None

        if isinstance(node, c_ast.BinaryOp):
            left = self.const_value(node.left)
            right = self.const_value(node.right)
            if left is None or right is None:
                return None
            if node.op == "+":
                return left + right
            if node.op == "-":
                return left - right
            if node.op == "*":
                return left * right
            if node.op == "/":
                return left // right if right else None
            if node.op == "<<":
                return left << right
            if node.op == ">>":
                return left >> right
            return None

        return None

    def array_len(self, node):
        #
        #  No dimension at all is a flexible array member, and contributes
        #  nothing to the size.  A dimension which cannot be worked out is
        #  a different thing: the array has a size and this tool does not
        #  know it, so every offset after it would be wrong.  Record that
        #  rather than quietly calling it zero.
        #
        if node.dim is None:
            return None

        value = self.const_value(node.dim)
        if value is None:
            self.unknown.add("array dimension '%s'" % expression_text(node.dim))
            return None

        return value

    def measure(self, node):
        """Return (size, align) for a type node."""
        if isinstance(node, (c_ast.PtrDecl, c_ast.FuncDecl)):
            return POINTER

        if isinstance(node, c_ast.ArrayDecl):
            size, align = self.measure(node.type)
            count = self.array_len(node)
            if count is None:
                #  A flexible member, or a dimension we could not read.
                return 0, align
            return size * count, align

        if isinstance(node, c_ast.TypeDecl):
            return self.measure(node.type)

        if isinstance(node, c_ast.Enum):
            spelled = ENUM_BASE.get(node.name)
            if spelled:
                if spelled in self.base:
                    return self.base[spelled]
                self.unknown.add(spelled)
                return 0, 1
            return self.base.get("int", (4, 4))

        if isinstance(node, (c_ast.Struct, c_ast.Union)):
            inner = node
            if inner.decls is None and inner.name:
                key = ("struct " if isinstance(node, c_ast.Struct) else "union ") + inner.name
                inner = self.records.get(key)
                if inner is None:
                    #  struct_sizes measures "struct in_addr" under that name.
                    if key in self.base:
                        return self.base[key]
                    self.unknown.add(key)
                    return 0, 1
            out = self.layout(inner)
            return out.size, out.align

        if isinstance(node, c_ast.IdentifierType):
            words = [w for w in node.names if w not in NOISE]
            spelled = " ".join(words) if words else "int"

            if spelled in self.opaque:
                self.unknown.add("%s (incomplete type, used by value)" % spelled)
                return 0, 1

            if spelled in self.base:
                return self.base[spelled]
            #  "unsigned" on its own, "signed char", and so on.
            joined = " ".join(node.names)
            if joined in self.base:
                return self.base[joined]
            if not words:
                return self.base["int"]

            if spelled in self.typedefs:
                return self.measure(self.typedefs[spelled])

            self.unknown.add(spelled)
            return 0, 1

        return 0, 1

    def attributes_for(self, node):
        key = None
        if isinstance(node, c_ast.Struct):
            key = node.name and ("struct " + node.name)
        elif isinstance(node, c_ast.Union):
            key = node.name and ("union " + node.name)

        if node.name and node.name in self.attrs:
            return self.attrs[node.name]
        if key and key in self.attrs:
            return self.attrs[key]
        return False, None

    def layout(self, node):
        """Lay out a struct or union node, and cache the result."""
        cached = self.laid_out.get(id(node))
        if cached is not None:
            return cached

        kind = "union" if isinstance(node, c_ast.Union) else "struct"
        tag = node.name
        out = Layout(kind, "(anonymous)" if (not tag or tag in SYNTHETIC) else tag)
        self.laid_out[id(node)] = out

        packed, aligned = self.attributes_for(node)
        out.packed = packed
        out.forced_align = aligned if isinstance(aligned, int) else None
        if isinstance(aligned, str):
            out.forced_align = None
            self.unknown.add("aligned(%s)" % aligned)

        if node.decls is None:
            return out

        if kind == "union":
            self.layout_union(node, out)
        else:
            self.layout_struct(node, out)

        return out

    def field_of(self, decl):
        """Turn one member declaration into a Field."""
        size, align = self.measure(decl.type)
        bits = None
        if getattr(decl, "bitsize", None) is not None:
            try:
                bits = int(decl.bitsize.value, 0)
            except (AttributeError, ValueError):
                bits = None

        name = decl.name
        if name is None:
            #  An anonymous struct or union member.
            inner = decl.type
            while isinstance(inner, c_ast.TypeDecl):
                inner = inner.type
            kind = "union" if isinstance(inner, c_ast.Union) else "struct"
            name = "(anonymous %s)" % kind

        return Field(name, self.name_of(decl.type), size, align, bits)

    def layout_struct(self, node, out):
        bit = 0                     #  current position, in bits
        align = 1

        for decl in node.decls:
            f = self.field_of(decl)

            if out.packed:
                f.align = 1

            if f.bits is not None:
                unit = (f.size or 4) * 8
                align = max(align, 1 if out.packed else f.align)

                if f.bits == 0:
                    #  A zero width field pushes the next one to a fresh unit.
                    if unit:
                        bit = ((bit + unit - 1) // unit) * unit
                    continue

                if not out.packed and unit:
                    start = (bit // unit) * unit
                    if bit + f.bits > start + unit:
                        bit = start + unit

                f.offset = bit // 8
                f.bit_offset = bit % 8
                bit += f.bits
            else:
                byte = (bit + 7) // 8
                if f.align > 1:
                    padded = ((byte + f.align - 1) // f.align) * f.align
                    f.pad_before = padded - byte
                    byte = padded
                f.offset = byte
                bit = (byte + f.size) * 8
                align = max(align, f.align)

            out.fields.append(f)

        size = (bit + 7) // 8
        if out.forced_align:
            align = max(align, out.forced_align)
        out.align = max(1, align)
        out.size = ((size + out.align - 1) // out.align) * out.align

        used = sum(f.size for f in out.fields if f.bits is None)
        used += sum(f.bits for f in out.fields if f.bits is not None) // 8
        out.padding = max(0, out.size - used)

    def layout_union(self, node, out):
        align = 1
        biggest = 0
        for decl in node.decls:
            f = self.field_of(decl)
            if out.packed:
                f.align = 1
            f.offset = 0
            out.fields.append(f)
            biggest = max(biggest, f.size)
            align = max(align, f.align)

        if out.forced_align:
            align = max(align, out.forced_align)
        out.align = max(1, align)
        out.size = ((biggest + out.align - 1) // out.align) * out.align
        out.padding = max(0, out.size - biggest)


#
#  ======================================================================
#  Suggesting a better order.
#  ======================================================================
#

def group_fields(out):
    """Group the fields into things that can be moved as a unit.

    A run of bitfields shares its storage, so the run moves together or not
    at all.  Everything else moves on its own.
    """
    groups, run = [], []

    for f in out.fields:
        if f.bits is not None:
            run.append(f)
            continue
        if run:
            groups.append(run)
            run = []
        groups.append([f])

    if run:
        groups.append(run)
    return groups


def group_metrics(group):
    """The alignment and byte cost of one group."""
    align = max(f.align for f in group)
    if group[0].bits is not None:
        bits = sum(f.bits for f in group)
        size = max((bits + 7) // 8, 1)
    else:
        size = group[0].size
    return align, size


def reorder(out):
    """Lay the same fields out largest alignment first.

    Padding exists because a small field sits in front of a large one, so
    sorting by alignment removes it.  Sorting by size within the same
    alignment keeps fields of a kind together, which reads better and costs
    nothing.
    """
    groups = group_fields(out)
    ordered = sorted(groups, key=lambda g: (-group_metrics(g)[0], -group_metrics(g)[1]))

    suggestion = Layout(out.kind, out.name)
    suggestion.packed = out.packed
    suggestion.forced_align = out.forced_align

    bit = 0
    align = 1

    for group in ordered:
        if group[0].bits is not None:
            unit = (group[0].size or 4) * 8
            for f in group:
                copy = Field(f.name, f.type_name, f.size, f.align, f.bits)
                if f.bits == 0:
                    if unit:
                        bit = ((bit + unit - 1) // unit) * unit
                    continue
                if not out.packed and unit:
                    start = (bit // unit) * unit
                    if bit + f.bits > start + unit:
                        bit = start + unit
                copy.offset = bit // 8
                copy.bit_offset = bit % 8
                bit += f.bits
                align = max(align, f.align)
                suggestion.fields.append(copy)
            continue

        f = group[0]
        copy = Field(f.name, f.type_name, f.size, f.align, None)
        byte = (bit + 7) // 8
        if f.align > 1:
            padded = ((byte + f.align - 1) // f.align) * f.align
            copy.pad_before = padded - byte
            byte = padded
        copy.offset = byte
        bit = (byte + f.size) * 8
        align = max(align, f.align)
        suggestion.fields.append(copy)

    size = (bit + 7) // 8
    if suggestion.forced_align:
        align = max(align, suggestion.forced_align)
    suggestion.align = max(1, align)
    suggestion.size = ((size + suggestion.align - 1) // suggestion.align) * suggestion.align

    used = sum(f.size for f in suggestion.fields if f.bits is None)
    used += sum(f.bits for f in suggestion.fields if f.bits is not None) // 8
    suggestion.padding = max(0, suggestion.size - used)

    return suggestion


#
#  ======================================================================
#  Turning runs of bool into bitfields.
#  ======================================================================
#

BOOL_TYPES = {"bool", "_Bool"}


def bool_runs(out):
    """Runs of two or more bool fields which sit next to each other.

    One bool on its own is usually free, because it drops into padding
    which exists anyway.  A run of them is not: each takes a whole byte,
    and the run pushes everything after it along.
    """
    runs, current = [], []

    for f in out.fields:
        if f.bits is None and f.type_name.strip() in BOOL_TYPES:
            current.append(f)
            continue
        if len(current) > 1:
            runs.append(current)
        current = []

    if len(current) > 1:
        runs.append(current)

    return runs


def with_bitfields(out, types):
    """The same structure with every run of bools written as bitfields.

    A run of eight bools costs eight bytes.  The same eight as one bit
    each cost four, and often less, because the rest of the storage unit
    can hold the next run too.
    """
    runs = bool_runs(out)
    if not runs:
        return None, 0

    in_a_run = set()
    for run in runs:
        for f in run:
            in_a_run.add(id(f))

    unit_size, unit_align = types.base.get("unsigned int", (4, 4))

    changed = Layout(out.kind, out.name)
    changed.packed = out.packed
    changed.forced_align = out.forced_align

    for f in out.fields:
        if id(f) in in_a_run:
            changed.fields.append(Field(f.name, "unsigned int", unit_size, unit_align, 1))
        else:
            changed.fields.append(Field(f.name, f.type_name, f.size, f.align, f.bits))

    relaid = relayout(changed)
    return relaid, sum(len(r) for r in runs)


def relayout(out):
    """Lay out a Layout's fields again, in the order they are already in."""
    fresh = Layout(out.kind, out.name)
    fresh.packed = out.packed
    fresh.forced_align = out.forced_align

    bit = 0
    align = 1

    for f in out.fields:
        copy = Field(f.name, f.type_name, f.size, f.align, f.bits)

        if f.bits is not None:
            unit = (f.size or 4) * 8
            align = max(align, 1 if out.packed else f.align)

            if f.bits == 0:
                if unit:
                    bit = ((bit + unit - 1) // unit) * unit
                continue

            if not out.packed and unit:
                start = (bit // unit) * unit
                if bit + f.bits > start + unit:
                    bit = start + unit

            copy.offset = bit // 8
            copy.bit_offset = bit % 8
            bit += f.bits
        else:
            byte = (bit + 7) // 8
            if f.align > 1:
                padded = ((byte + f.align - 1) // f.align) * f.align
                copy.pad_before = padded - byte
                byte = padded
            copy.offset = byte
            bit = (byte + f.size) * 8
            align = max(align, f.align)

        fresh.fields.append(copy)

    size = (bit + 7) // 8
    if fresh.forced_align:
        align = max(align, fresh.forced_align)
    fresh.align = max(1, align)
    fresh.size = ((size + fresh.align - 1) // fresh.align) * fresh.align

    used = sum(f.size for f in fresh.fields if f.bits is None)
    used += sum(f.bits for f in fresh.fields if f.bits is not None) // 8
    fresh.padding = max(0, fresh.size - used)

    return fresh


#
#  ======================================================================
#  Reporting.
#  ======================================================================
#

def describe(f):
    if f.bits is not None:
        return "%s : %d" % (f.name, f.bits)
    return f.name


def print_layout(out, indent="  "):
    print("%s%-8s %-6s %-6s %-34s %s" % (indent, "offset", "size", "align", "field", "type"))
    print("%s%-8s %-6s %-6s %-34s %s" % (indent, "-" * 8, "-" * 6, "-" * 6, "-" * 34, "-" * 20))

    for f in out.fields:
        if f.pad_before:
            print("%s%-8s %-6d %-6s %s" %
                  (indent, "", f.pad_before, "", "..... %d byte%s of padding" %
                   (f.pad_before, "" if f.pad_before == 1 else "s")))

        if f.bits is not None:
            where = "%d:%d" % (f.offset, f.bit_offset)
            size = "%db" % f.bits
        else:
            where = str(f.offset)
            size = str(f.size)

        print("%s%-8s %-6s %-6d %-34s %s" %
              (indent, where, size, f.align, describe(f), f.type_name))

    tail = out.size - end_of(out)
    if tail > 0:
        print("%s%-8s %-6d %-6s %s" %
              (indent, "", tail, "", "..... %d byte%s of padding at the end" %
               (tail, "" if tail == 1 else "s")))


def end_of(out):
    """The first byte after the last field."""
    last = 0
    for f in out.fields:
        if f.bits is not None:
            last = max(last, f.offset + max(1, (f.bit_offset + f.bits + 7) // 8))
        else:
            last = max(last, f.offset + f.size)
    return last


def report(out, types, want_reorder):
    header = "%s %s" % (out.kind, out.name)
    print()
    print(header)
    print("=" * len(header))

    notes = []
    if out.packed:
        notes.append("packed")
    if out.forced_align:
        notes.append("aligned to %d" % out.forced_align)

    waste = (out.padding * 100.0 / out.size) if out.size else 0.0
    print("  size %d bytes, alignment %d, padding %d byte%s (%.0f%%)%s" %
          (out.size, out.align, out.padding, "" if out.padding == 1 else "s", waste,
           ("   [" + ", ".join(notes) + "]") if notes else ""))
    print()
    print_layout(out)

    if not want_reorder:
        return

    better = reorder(out)
    print()

    if better.size >= out.size:
        if out.forced_align and better.padding < out.padding:
            print("  Reordering removes %d bytes of padding between fields, but the" %
                  (out.padding - better.padding))
            print("  structure is aligned to %d, so its size does not change." % out.forced_align)
        else:
            print("  Already in the best order; reordering would not make it smaller.")
        return

    saved = out.size - better.size
    print("  Reordering saves %d byte%s: %d -> %d (%.0f%% smaller)" %
          (saved, "" if saved == 1 else "s", out.size, better.size,
           saved * 100.0 / out.size))
    print()
    print_layout(better)


#
#  ======================================================================
#  The same thing, as markdown.
#  ======================================================================
#

def md_table(out):
    lines = ["| offset | size | align | field | type |",
             "|---|---|---|---|---|"]

    for f in out.fields:
        if f.pad_before:
            lines.append("| | %d | | *padding* | |" % f.pad_before)

        if f.bits is not None:
            where = "%d:%d" % (f.offset, f.bit_offset)
            size = "%d bits" % f.bits
            name = "%s : %d" % (f.name, f.bits)
        else:
            where, size, name = str(f.offset), str(f.size), f.name

        lines.append("| %s | %s | %d | `%s` | `%s` |" % (where, size, f.align, name, f.type_name))

    tail = out.size - end_of(out)
    if tail > 0:
        lines.append("| | %d | | *padding at the end* | |" % tail)

    return lines


def md_order(out):
    """The field order, as a list which can be pasted back into the header."""
    lines = ["```c"]
    for f in out.fields:
        if f.bits is not None:
            lines.append("\t%s\t%s : %d;" % (f.type_name, f.name, f.bits))
        else:
            lines.append("\t%s\t%s;" % (f.type_name, f.name))
    lines.append("```")
    return lines


def markdown(out, types, header_name):
    """One structure, as markdown.  Returns (lines, saved, bitfield_note)."""
    lines = []
    saved = 0

    notes = []
    if out.packed:
        notes.append("packed")
    if out.forced_align:
        notes.append("aligned to %d" % out.forced_align)
    note = (" (%s)" % ", ".join(notes)) if notes else ""

    better = reorder(out)
    saved = max(0, out.size - better.size)

    lines.append("## `%s %s`%s" % (out.kind, out.name, note))
    lines.append("")

    if saved == 0:
        #  The whole entry, for something which cannot be improved.
        lines.append("%d bytes, alignment %d, %d bytes of padding.  "
                     "Already sized correctly; rearranging the fields would not "
                     "make it smaller." % (out.size, out.align, out.padding))
        lines.append("")
    else:
        lines.append("%d bytes, alignment %d, **%d bytes of padding**." %
                     (out.size, out.align, out.padding))
        lines.append("")
        lines.append("**Rearranging saves %d byte%s: %d to %d, %.0f%% smaller.**" %
                     (saved, "" if saved == 1 else "s", out.size, better.size,
                      saved * 100.0 / out.size))
        lines.append("")
        lines.append("Current layout:")
        lines.append("")
        lines.extend(md_table(out))
        lines.append("")
        lines.append("Suggested order:")
        lines.append("")
        lines.extend(md_order(better))
        lines.append("")

    #  Bools which would be cheaper as bitfields.  Measured against the
    #  reordered size, so that a saving reordering would have given anyway
    #  is not claimed twice.
    packed_bools, count = with_bitfields(out, types)
    bit_note = None
    if packed_bools is not None:
        best_bits = reorder(packed_bools)
        extra = better.size - best_bits.size
        if extra > 0:
            bit_note = (out, count, better.size, best_bits.size, extra,
                        [f.name for run in bool_runs(out) for f in run])

    return lines, saved, bit_note


def markdown_report(header_path, records, types):
    """The whole report for one header."""
    name = header_path.split("/")[-1]

    #
    #  A header with nothing in it still gets a report, so that a make
    #  rule can name the file it produces.  It gets the short form: the
    #  explanation below is about structures, and there are none.
    #
    if not records:
        return "\n".join(["# `%s`: structure alignment" % name,
                           "",
                           "`%s` declares no structures, so there is nothing "
                           "to lay out." % header_path,
                           "",
                           "Generated by `scripts/build/alignment.py`.",
                           ""])

    lines = ["# `%s`: structure alignment" % name,
             "",
             "How the structures in `%s` are laid out in memory, and whether "
             "reordering their fields would use less of it." % header_path,
             "",
             "A field has to start at an address the machine can use for its "
             "type, so a small field in front of a large one leaves a gap.  "
             "That gap is memory the structure pays for and cannot use.",
             "",
             "A suggested order is a suggestion.  Some structures are "
             "written in the order they are for a reason: `fr_pair_t` "
             "overlays part of an `fr_value_box_t`, wire formats have to "
             "match the packet, and a field a macro reaches by name has to "
             "stay where the macro expects it.  Check the code before "
             "moving anything.",
             "",
             "Generated by `scripts/build/alignment.py`.",
             ""]

    body = []
    total_saved = 0
    bit_notes = []
    improvable = 0

    for out in sorted(records, key=lambda o: (-(o.padding), o.name)):
        part, saved, bit_note = markdown(out, types, name)
        body.extend(part)
        total_saved += saved
        if saved:
            improvable += 1
        if bit_note:
            bit_notes.append(bit_note)

    lines.append("## Summary")
    lines.append("")
    lines.append("%d structure%s examined.  %d could be made smaller by "
                 "reordering, saving %d byte%s in total." %
                 (len(records), "" if len(records) == 1 else "s", improvable,
                  total_saved, "" if total_saved == 1 else "s"))
    lines.append("")
    lines.extend(body)

    if bit_notes:
        lines.append("---")
        lines.append("")
        lines.append("## Secondary report: bool fields which would be cheaper as bitfields")
        lines.append("")
        lines.append("Each of these structures has two or more `bool` fields "
                     "next to each other.  A `bool` takes a whole byte, so a "
                     "run of them costs one byte each.  Written as "
                     "`unsigned int name : 1` they share a single four byte "
                     "unit instead.")
        lines.append("")
        lines.append("The saving below is what bitfields give *on top of* "
                     "reordering, so nothing is counted twice.")
        lines.append("")
        lines.append("| structure | bools | after reordering | with bitfields | further saving |")
        lines.append("|---|---|---|---|---|")
        for out, count, was, now, extra, names in bit_notes:
            lines.append("| `%s` | %d | %d bytes | %d bytes | **%d bytes** |" %
                         (out.name, count, was, now, extra))
        lines.append("")
        for out, count, was, now, extra, names in bit_notes:
            lines.append("### `%s`" % out.name)
            lines.append("")
            lines.append("The run%s of bools: %s." %
                         ("" if count == 1 else "s",
                          ", ".join("`%s`" % n for n in names)))
            lines.append("")
            lines.append("```c")
            for n in names:
                lines.append("\tunsigned int\t%s : 1;" % n)
            lines.append("```")
            lines.append("")

    return "\n".join(lines)


#
#  ======================================================================
#  Driving it.
#  ======================================================================
#

#
#  pycparser needs every typedef declared before it can parse a use of it:
#  without one it cannot tell "size_t blocks;" from an expression.  These
#  are declared here so that a header does not have to include stdint.h,
#  which this tool would not be able to follow anyway.
#
#  The sizes come from the model table, not from these declarations, so the
#  base type each one is spelled with does not matter.
#
STANDARD_TYPEDEFS = """
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long int64_t;
typedef unsigned long uint64_t;
typedef signed char int_least8_t;
typedef unsigned char uint_least8_t;
typedef short int_least16_t;
typedef unsigned short uint_least16_t;
typedef int int_least32_t;
typedef unsigned int uint_least32_t;
typedef long int_least64_t;
typedef unsigned long uint_least64_t;
typedef signed char int_fast8_t;
typedef unsigned char uint_fast8_t;
typedef short int_fast16_t;
typedef unsigned short uint_fast16_t;
typedef int int_fast32_t;
typedef unsigned int uint_fast32_t;
typedef long int_fast64_t;
typedef unsigned long uint_fast64_t;
typedef long intmax_t;
typedef unsigned long uintmax_t;
typedef long intptr_t;
typedef unsigned long uintptr_t;
typedef unsigned long size_t;
typedef long ssize_t;
typedef long ptrdiff_t;
typedef long time_t;
typedef long off_t;
typedef long off64_t;
typedef int pid_t;
typedef int wchar_t;
typedef unsigned short char16_t;
typedef unsigned int char32_t;
typedef _Bool bool;
typedef void *va_list;
typedef struct _IO_FILE FILE;
"""


C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while", "_Bool", "_Atomic", "_Complex",
}


def guess_missing_types(source):
    """Names used where a type belongs, which nothing in the input declares.

    A guess, and only used to make a parse failure say something useful.
    pycparser reports "Invalid specifier list" when it meets an identifier
    it does not know is a type, without saying which one, and that is not
    much help when the fix is to name another header.
    """
    declared = set(re.findall(r"\btypedef\b[^;{]*?(\w+)\s*;", source))
    declared |= set(re.findall(r"\}\s*(\w+)\s*;", source))
    #
    #  "typedef int (*fr_uri_escape_func_t)(fr_value_box_t *vb);" does not
    #  end in the name, so the two patterns above walk straight past it and
    #  the name is then reported as the missing one.
    #
    declared |= set(re.findall(r"\btypedef\b[^;]*?\(\s*\*+\s*(\w+)\s*\)\s*\(", source))
    known = declared | C_KEYWORDS | set(LP64) | set(LLP64)

    missing = set()
    #
    #  The const may sit on either side of the type name: FreeRADIUS writes
    #  "fr_sbuff_term_t const *terminals", not "const fr_sbuff_term_t *".
    #
    member = re.compile(
        r"^[ \t]*(?:const[ \t]+|volatile[ \t]+)*"
        r"([A-Za-z_]\w*)"
        r"(?:[ \t]+(?:const|volatile))*"
        r"[ \t]+\**[ \t]*\w+[ \t]*(?:\[[^\]]*\])?[ \t]*[;:,]",
        re.M)

    for m in member.finditer(source):
        name = m.group(1)
        if name not in known:
            missing.add(name)

    return missing


def opaque_typedefs(names):
    """Declare a type so pycparser can parse it.

    Used for anything named with --size.  The spelling is irrelevant: the
    size comes from the override, which measure() consults first.
    """
    #
    #  A name holding a space is a tag, "struct in_addr".  pycparser parses
    #  a use of it on its own, as an incomplete type, and measure() takes
    #  its size from the override, so nothing needs declaring here.
    #
    return "".join("typedef int %s;\n" % n
                   for n in sorted(names) if " " not in n)


def load_sizes(path):
    """Read type sizes from the output of radsizes, or a tool like it.

    Each line is a type name, its size in bytes, and the word "bytes":

        fr_dlist_t              	16	bytes

    A fourth column, if there is one, is the alignment.  radsizes does not
    print it, and it is worth having, because a structure's alignment
    cannot be worked out from its size: fr_dlist_t is sixteen bytes and
    aligned to eight.  src/lib/alloc/struct_sizes.c prints it.

    Without a fourth column the alignment is taken to be the largest power
    of two which divides the size, up to eight.  That is right for anything
    built out of pointers and integers, which is nearly everything, and
    --size overrides it where it is not.

    If path is executable it is run.  Otherwise it is read as a file of
    captured output.
    """
    import os
    import subprocess

    if os.path.isfile(path) and os.access(path, os.X_OK):
        try:
            done = subprocess.run([path], capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as e:
            die("could not run %s: %s" % (path, e))
        if done.returncode != 0:
            die("%s exited %d" % (path, done.returncode))
        text = done.stdout
    else:
        try:
            text = open(path).read()
        except OSError as e:
            die(str(e))

    sizes = {}
    for line in text.split("\n"):
        #
        #  The columns are separated by tabs, so a name may hold a space:
        #  struct_sizes prints "struct in_addr" as one field.  Fall back to
        #  splitting on any whitespace for output which has no tabs.
        #
        if "\t" in line:
            parts = [f.strip() for f in line.split("\t") if f.strip()]
        else:
            parts = line.split()
        #  jlibtool prints its environment on stdout; skip anything which is
        #  not a name followed by a number.
        if len(parts) < 2:
            continue
        name, size = parts[0], parts[1]
        if not size.isdigit():
            continue

        size = int(size)
        if len(parts) >= 4 and parts[3].isdigit():
            align = int(parts[3])
        else:
            align = 1
            while align < 8 and (size % (align * 2)) == 0:
                align *= 2

        sizes[name] = (size, align)

    return sizes


def collect_defines(text):
    """Object like #defines whose body could be an integer expression.

    "#define SBUFF_CHAR_CLASS UINT8_MAX + 1" is an array dimension in the
    same header, so reading it here saves naming it on the command line.
    Anything with arguments, or a body which is not arithmetic over names
    and numbers, is passed over.
    """
    found = {}

    for m in re.finditer(r"^[ \t]*#[ \t]*define[ \t]+(\w+)[ \t]+([^\n]*)$",
                         text, re.M):
        name, body = m.group(1), m.group(2).strip()

        #  A body continued onto the next line is not a plain constant.
        if body.endswith("\\"):
            continue
        if not body:
            continue
        if not re.fullmatch(r"[\w\s+\-*/()<>]+", body):
            continue
        #  A bare rename of one name to another is not worth following.
        found[name] = body

    return found


def parse_defines(items):
    """Split -D arguments into plain names and function like macros.

    A plain "-D NAME" or "-D NAME=VALUE" answers #ifdef and supplies the
    argument to aligned().  A "-D NAME(x)=TYPE" is substituted wherever
    NAME(...) appears, which is how a member declared through a macro,
    such as FR_DLIST_ENTRY(list) entry;, can be understood.  The macro's
    arguments are discarded: only the type it stands for matters here.
    """
    defines = {}
    macros = {}

    for item in items or []:
        name, _, value = item.partition("=")
        name = name.strip()

        m = re.fullmatch(r"(\w+)\s*\(([^)]*)\)", name)
        if m:
            macros[m.group(1)] = value.strip()
            continue

        defines[name] = value.strip() if value else "1"

    return defines, macros


def expand_macros(text, macros, plain=None):
    """Replace NAME(...) with what NAME stands for.

    "plain" does the same for a macro with no arguments, which is how a
    header can declare fields through a macro: stats.h writes
    "STATS_HEADER_COMMON;" where a field declaration belongs.
    """
    for name, body in macros.items():
        text = re.sub(r"\b" + re.escape(name) + r"\s*\([^()]*\)", body, text)
    for name, body in (plain or {}).items():
        text = re.sub(r"\b" + re.escape(name) + r"\b", body, text)
    return text


def parse_sizes(items):
    sizes = {}
    for item in items or []:
        if "=" not in item:
            die("--size wants TYPE=BYTES, got '%s'" % item)
        name, value = item.split("=", 1)
        try:
            if ":" in value:
                size, align = value.split(":", 1)
                sizes[name.strip()] = (int(size), int(align))
            else:
                n = int(value)
                sizes[name.strip()] = (n, n if n in (1, 2, 4, 8, 16) else 1)
        except ValueError:
            die("--size wants TYPE=BYTES or TYPE=BYTES:ALIGN, got '%s'" % item)
    return sizes


def main():
    ap = argparse.ArgumentParser(
        description="Report the alignment and padding of C structures.",
        epilog="Headers are not run through a real preprocessor, so #include is "
               "ignored.  Name every header the structure depends on, and use -D "
               "for the build flags that change it.")
    ap.add_argument("headers", nargs="+", help="header files to read")
    ap.add_argument("-r", "--reorder", action="store_true",
                    help="also print the order which uses the least memory")
    ap.add_argument("-s", "--struct", action="append", metavar="NAME",
                    help="report only this structure, may be repeated")
    ap.add_argument("-D", "--define", action="append", metavar="NAME[=VALUE]",
                    help="treat NAME as defined, for #ifdef.  NAME(x)=TYPE also "
                         "works, for a member declared through a macro")
    ap.add_argument("--size", action="append", metavar="TYPE=BYTES[:ALIGN]",
                    help="size of a type this tool cannot see, may be repeated")
    ap.add_argument("--macro", action="append", metavar="NAME=TEXT",
                    help="replace NAME with TEXT wherever it appears.  For a "
                         "macro with no arguments which stands for one or more "
                         "field declarations, which -D does not cover")
    ap.add_argument("--dump", action="store_true",
                    help="print the source handed to the parser, numbered, and "
                         "stop.  The line numbers match the ones a parse error "
                         "reports")
    ap.add_argument("--opaque", action="append", metavar="TYPE",
                    help="TYPE is incomplete (void, or a forward declared "
                         "struct) and is only used through a pointer.  Declares "
                         "it so the headers parse, and complains if a field "
                         "uses it by value")
    ap.add_argument("--sizes", action="append", metavar="PATH",
                    help="take type sizes from radsizes, or from a file of its "
                         "output; may be repeated.  An executable is run, "
                         "anything else is read")
    ap.add_argument("--model", choices=("lp64", "llp64"), default="lp64",
                    help="lp64 for Linux and macOS (default), llp64 for Windows")
    ap.add_argument("--all", action="store_true",
                    help="include structures with no padding, which are hidden by default")
    ap.add_argument("--markdown", metavar="FILE",
                    help="write a markdown report to FILE instead of printing a "
                         "table.  Implies --all, since a report saying a "
                         "structure is already right is worth having")
    args = ap.parse_args()

    defines, macros = parse_defines(args.define)
    plain_macros = {}
    for item in args.macro or []:
        if "=" not in item:
            die("--macro wants NAME=TEXT, got '%s'" % item)
        name, body = item.split("=", 1)
        plain_macros[name.strip()] = body

    #  Sizes from a tool come first, so that --size on the command line
    #  still wins over them.
    overrides = {}
    for path in args.sizes or []:
        overrides.update(load_sizes(path))
    overrides.update(parse_sizes(args.size))
    model = LP64 if args.model == "lp64" else LLP64

    text_parts, attrs = [], {}
    harvested = {}
    for path in args.headers:
        try:
            raw = open(path).read()
        except OSError as e:
            die(str(e))
        harvested.update(collect_defines(strip_comments(raw)))
        clean, found = sanitise(raw, defines, macros, plain_macros)
        text_parts.append(clean)
        attrs.update(found)

    #  A -D on the command line wins over what the header says.
    constants = harvested
    constants.update(defines)

    incomplete = set(args.opaque or ())
    preamble = STANDARD_TYPEDEFS + opaque_typedefs(set(overrides) | incomplete)
    source = preamble + "\n".join(text_parts)

    if args.dump:
        for number, line in enumerate(source.split("\n"), 1):
            print("%5d  %s" % (number, line))
        return 0

    try:
        ast = c_parser.CParser().parse(source, "<headers>")
    except Exception as e:
        missing = guess_missing_types(source)
        note = ""
        if missing:
            note = ("\n       These look like types nothing here declares:\n"
                    "         %s\n"
                    "       Name the header which defines them, or give\n"
                    "       --size %s=BYTES for each."
                    % (", ".join(sorted(missing)), sorted(missing)[0]))
        die("could not parse the headers: %s\n"
            "\n"
            "       This tool does not follow #include, so every type a\n"
            "       structure uses has to come from a header named on the\n"
            "       command line.%s" % (e, note))

    types = Types(model, overrides, attrs, opaque=incomplete, consts=constants)
    types.learn(ast)

    if args.markdown:
        args.all = True

    wanted = set(args.struct or [])
    seen = []

    for key, node in types.records.items():
        tag = key.split(None, 1)[1]
        if tag in SYNTHETIC:
            continue
        if wanted and tag not in wanted and key not in wanted:
            continue
        out = types.layout(node)
        if not args.all and not wanted and out.padding == 0:
            continue
        seen.append(out)

    #  A typedef of an anonymous struct is the common FreeRADIUS spelling,
    #  and has no tag for the loop above to find.
    for name, node in types.typedefs.items():
        inner = node
        while isinstance(inner, c_ast.TypeDecl):
            inner = inner.type
        if not isinstance(inner, (c_ast.Struct, c_ast.Union)) or inner.decls is None:
            continue
        if inner.name:
            continue                #  already reported through its tag
        if wanted and name not in wanted:
            continue
        out = types.layout(inner)
        out.name = name
        if not args.all and not wanted and out.padding == 0:
            continue
        seen.append(out)

    if types.unknown:
        out = sys.stderr if args.markdown else sys.stdout
        print(file=out)
        print("Types this tool could not size, counted as zero:", file=out)
        for name in sorted(types.unknown):
            print("  %s" % name, file=out)
        macros = [u for u in types.unknown if u.startswith("aligned(")]
        if macros:
            name = macros[0][len("aligned("):-1]
            print("For %s, give -D %s=VALUE." % (macros[0], name), file=out)
        dims = [u for u in types.unknown if u.startswith("array dimension ")]
        if dims:
            print("An array dimension is fixed with -D NAME=VALUE, not --size.",
                  file=out)
        others = [u for u in types.unknown
                  if not u.startswith("aligned(") and not u.startswith("array dimension ")]
        if others:
            print("Name the header which defines them, or give --size %s=BYTES." %
                  sorted(others)[0], file=out)
        if args.markdown:
            #
            #  A structure containing a field measured as zero has the
            #  wrong size, and every claim in the report follows from the
            #  size.  Say so and write nothing.
            #
            print("alignment.py: %s not written" % args.markdown, file=sys.stderr)
        return 1

    not_found = False
    if wanted:
        missing = wanted - {o.name for o in seen}
        for name in sorted(missing):
            print("alignment.py: no structure called '%s' in those headers" % name,
                  file=sys.stderr)
        not_found = bool(missing)

    if not seen:
        if args.markdown:
            try:
                with open(args.markdown, "w") as fp:
                    fp.write(markdown_report(args.headers[0], [], types))
                    fp.write("\n")
            except OSError as e:
                die(str(e))
            return 1 if not_found else 0
        if args.all or wanted:
            print("Nothing to report.")
        else:
            print("No structure has any padding.  Use --all to list them anyway.")
        return 1 if not_found else 0

    if args.markdown:
        text = markdown_report(args.headers[0], seen, types)
        try:
            with open(args.markdown, "w") as fp:
                fp.write(text)
                fp.write("\n")
        except OSError as e:
            die(str(e))
        return 1 if not_found else 0

    print("%d structure%s, %s model, pointers are %d bytes" %
          (len(seen), "" if len(seen) == 1 else "s", args.model, POINTER[0]))

    for out in sorted(seen, key=lambda o: -o.padding):
        report(out, types, args.reorder)

    return 1 if not_found else 0


if __name__ == "__main__":
    sys.exit(main())
