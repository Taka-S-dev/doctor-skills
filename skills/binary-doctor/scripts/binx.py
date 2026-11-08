#!/usr/bin/env python3
"""Binary save-file analysis for root-cause investigation (stdlib only).

Commands: overview, view, decode, diff, multi, check, report. Run with -h for options.
"""
import argparse
import ast
import bisect
import hashlib
import html
import json
import math
import os
import re
import struct
import sys
import zlib
from collections import Counter
from difflib import SequenceMatcher

# ---------------------------------------------------------------- formatting


def hexs(b, limit=32):
    s = b[:limit].hex(" ")
    return s + (f" …(+{len(b) - limit})" if len(b) > limit else "")


def ascii_of(b, limit=32):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b[:limit])


FILLS = [
    (b"\xcc", "MSVC 未初期化スタック (CC)"),
    (b"\xcd", "MSVC 未初期化ヒープ (CD)"),
    (b"\xdd", "MSVC 解放済みヒープ (DD)"),
    (b"\xfd", "MSVC ヒープのガード (FD)"),
    (b"\xab", "HeapAlloc のガード (AB)"),
    (b"\xee\xfe", "解放済みヒープ (FEEEFEEE)"),
    (b"\x0d\xf0\xad\xba", "未初期化 LocalAlloc (BAADF00D)"),
    (b"\xef\xbe\xad\xde", "DEADBEEF"),
    (b"\x00", "ゼロ埋め"),
    (b"\xff", "FF 埋め"),
]


def fill_name(b):
    if len(b) < 2:
        return None
    for pat, name in FILLS:
        if b == (pat * (len(b) // len(pat) + 1))[: len(b)]:
            return name
    return None


def plausible_float(v):
    return math.isfinite(v) and 1e-6 < abs(v) < 1e12


def hints(x, y, labels=("A", "B")):
    out = []
    n = len(y)
    if x and len(x) == n and x != y:
        if n in (2, 4, 8) and y == x[::-1]:
            out.append("バイト順が逆（エンディアン疑い）")
        if n in (1, 2, 4, 8):
            ux, uy = int.from_bytes(x, "little"), int.from_bytes(y, "little")
            out.append(f"LE整数 {ux} → {uy} (差 {uy - ux:+d})")
        if n in (4, 8):
            fmt = "<f" if n == 4 else "<d"
            fx, fy = struct.unpack(fmt, x)[0], struct.unpack(fmt, y)[0]
            if plausible_float(fx) and plausible_float(fy):
                out.append(f"浮動小数なら {fx:g} → {fy:g}")
    for label, b in zip(labels, (x, y)):
        name = fill_name(b)
        if name:
            out.append(f"{label} は {name}")
    return out


# ------------------------------------------------------------ safe expression


def _path(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_path(node.value)}.{node.attr}"
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
        return f"{_path(node.value)}[{node.slice.value}]"
    raise ValueError("式に使えない構文です")


MAX_SHIFT = 64


def _shift_left(a, b):
    # Shift amounts can come from corrupt files, and a huge one would exhaust memory.
    if not 0 <= b <= MAX_SHIFT:
        raise ValueError(f"シフト量 {b} は 0 から {MAX_SHIFT} の範囲外です")
    return a << b


BINOPS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a // b if isinstance(a, int) and isinstance(b, int) else a / b,
    ast.FloorDiv: lambda a, b: a // b,
    ast.Mod: lambda a, b: a % b,
    ast.LShift: _shift_left,
    ast.RShift: lambda a, b: a >> b,
    ast.BitAnd: lambda a, b: a & b,
    ast.BitOr: lambda a, b: a | b,
    ast.BitXor: lambda a, b: a ^ b,
}
CMPOPS = {
    ast.Eq: lambda a, b: a == b,
    ast.NotEq: lambda a, b: a != b,
    ast.Lt: lambda a, b: a < b,
    ast.LtE: lambda a, b: a <= b,
    ast.Gt: lambda a, b: a > b,
    ast.GtE: lambda a, b: a >= b,
}


EXPR_ERRORS = (KeyError, ValueError, SyntaxError, TypeError, ZeroDivisionError, AttributeError, OverflowError, MemoryError)


def eval_expr(src, env, sizes=None):
    src = re.sub(r"\b(0[xX][0-9a-fA-F]+|\d+)[uUlL]+\b", r"\1", src)
    src = src.replace("&&", " and ").replace("||", " or ")
    src = re.sub(r"!(?!=)", " not ", src)

    def ev(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)):
            return n.value
        if isinstance(n, ast.BinOp) and type(n.op) in BINOPS:
            return BINOPS[type(n.op)](ev(n.left), ev(n.right))
        if isinstance(n, ast.UnaryOp):
            v = ev(n.operand)
            if isinstance(n.op, ast.USub):
                return -v
            if isinstance(n.op, ast.UAdd):
                return v
            if isinstance(n.op, ast.Invert):
                return ~v
            if isinstance(n.op, ast.Not):
                return not v
        if isinstance(n, ast.Compare):
            left = ev(n.left)
            for op, right_node in zip(n.ops, n.comparators):
                right = ev(right_node)
                if not CMPOPS[type(op)](left, right):
                    return False
                left = right
            return True
        if isinstance(n, ast.BoolOp):
            vals = [ev(v) for v in n.values]
            return all(vals) if isinstance(n.op, ast.And) else any(vals)
        if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "sizeof" and sizes:
            return sizes[_path(n.args[0])].size
        p = _path(n)
        if p not in env:
            raise KeyError(p)
        return env[p]

    return ev(ast.parse(src.strip(), mode="eval").body)


# ----------------------------------------------------------------- C parsing


class Prim:
    def __init__(self, name, size, kind, names=None):
        self.name, self.size, self.align, self.kind, self.names = name, size, size or 1, kind, names


class Array:
    def __init__(self, elem, n):
        self.elem, self.n, self.size, self.align = elem, n, elem.size * n, elem.align
        self.name = f"{elem.name}[{n}]"


class DynArray:
    """An array whose length is only known while reading a file.

    mode is "expr" (length expression), "zstr" (through the first NUL),
    "rest" (to end of file) or "until" (through the element where expr holds).
    """

    def __init__(self, elem, mode, expr):
        self.elem, self.mode, self.expr, self.size, self.align = elem, mode, expr, 0, elem.align
        self.name = f"{elem.name}[...]"


class Cond:
    def __init__(self, expr, then, otherwise):
        self.expr, self.then, self.otherwise = expr, then, otherwise


class Field:
    def __init__(self, name, type_, offset, bits=None):
        self.name, self.type, self.offset, self.bits = name, type_, offset, bits


class Struct:
    def __init__(self, name):
        self.name, self.fields, self.size, self.align, self.incomplete = name, [], 0, 1, True
        self.dynamic, self.body = False, []


class Skip(Exception):
    """The statement declares no stored data (a method, static member, ...)."""


class Unknown(Exception):
    """The statement may declare stored data but could not be parsed."""


TOKEN = re.compile(
    r"[A-Za-z_]\w*|0[xX][0-9a-fA-F]+[uUlL]*|\d+(?:\.\d+)?[uUlLfF]*|::|<<|>>|==|!=|<=|>=|&&|\|\||\"[^\"\n]*\"|'[^'\n]*'|\S"
)
QUALS = {"const", "volatile", "mutable", "inline", "extern", "register", "constexpr", "typename"}
MSVC_SIZED = {"__int8": 1, "__int16": 2, "__int32": 4, "__int64": 8}
WORDS = {"unsigned", "signed", "short", "long", "int", "char", "float", "double", "void", "bool", "_Bool", "wchar_t", *MSVC_SIZED}
IDENT = re.compile(r"[A-Za-z_]\w*$")


class Defs:
    def __init__(self, ptr=8, long_=4, pack=None):
        self.ptr, self.long, self.default_pack, self.pack = ptr, long_, pack, pack
        self.pack_stack, self.constants, self.warnings = [], {}, []
        self.forward, self.forced, self.layout_warnings = {}, set(), []
        self.scopes = []
        self.toks, self.i = [], 0
        self.types = {}
        s, u, wide = "i", "u", 4 if long_ == 8 else 2
        table = {
            "int8_t": (1, s), "uint8_t": (1, u), "int16_t": (2, s), "uint16_t": (2, u),
            "int32_t": (4, s), "uint32_t": (4, u), "int64_t": (8, s), "uint64_t": (8, u),
            "s8": (1, s), "u8": (1, u), "s16": (2, s), "u16": (2, u), "s32": (4, s), "u32": (4, u),
            "s64": (8, s), "u64": (8, u), "i8": (1, s), "i16": (2, s), "i32": (4, s), "i64": (8, s),
            "f32": (4, "f"), "f64": (8, "f"), "BYTE": (1, u), "UCHAR": (1, u), "CHAR": (1, "c"),
            "WORD": (2, u), "USHORT": (2, u), "SHORT": (2, s), "DWORD": (4, u), "UINT": (4, u),
            "ULONG": (4, u), "INT": (4, s), "LONG": (4, s), "BOOL": (4, s), "BOOLEAN": (1, "b"),
            "QWORD": (8, u), "ULONGLONG": (8, u), "LONGLONG": (8, s), "INT8": (1, s), "UINT8": (1, u),
            "INT16": (2, s), "UINT16": (2, u), "INT32": (4, s), "UINT32": (4, u), "INT64": (8, s),
            "UINT64": (8, u), "FLOAT": (4, "f"), "DOUBLE": (8, "f"), "WCHAR": (2, "w"),
            "size_t": (ptr, u), "ssize_t": (ptr, s), "intptr_t": (ptr, s), "uintptr_t": (ptr, u),
            "ptrdiff_t": (ptr, s), "time_t": (8, s), "char16_t": (2, "w"), "char32_t": (4, u),
            "char8_t": (1, "c"), "HANDLE": (ptr, "p"), "LPVOID": (ptr, "p"), "PVOID": (ptr, "p"),
            "wchar_t": (wide, "w"),
        }
        for k, (size, kind) in table.items():
            self.types[k] = Prim(k, size, kind)

    # ---- token stream
    def peek(self, n=0):
        while self.i < len(self.toks) and self.toks[self.i].startswith("#pack:"):
            self._apply_pack(self.toks[self.i][6:])
            self.i += 1
        j = self.i + n
        return self.toks[j] if j < len(self.toks) else ""

    def take(self):
        t = self.peek()
        self.i += 1
        return t

    def expect(self, t):
        if self.peek() != t:
            raise Unknown(f"{t} の位置に {self.peek()!r}")
        self.take()

    def _apply_pack(self, arg):
        parts = [p.strip() for p in arg.split(",") if p.strip()]
        if not parts:
            self.pack = self.default_pack
            return
        nums = [int(p, 0) for p in parts if re.fullmatch(r"\d+|0x[0-9a-fA-F]+", p)]
        if parts[0] == "push":
            self.pack_stack.append(self.pack)
        elif parts[0] == "pop":
            self.pack = self.pack_stack.pop() if self.pack_stack else self.default_pack
        if nums:
            self.pack = nums[-1]

    # ---- entry
    def feed(self, text):
        text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
        text = re.sub(r"//[^\n]*", " ", text)
        text = text.replace("\\\n", " ")
        text = re.sub(r"\[\[.*?\]\]", " ", text, flags=re.S)
        toks = []
        for m in re.finditer(r"(?:static\s+)?(?:const|constexpr)\s+[\w\s]+?\s(\w+)\s*=\s*([^;,{}]+);", text):
            self._define(m.group(1), m.group(2))
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("#"):
                m = re.match(r"#\s*define\s+(\w+)\s+(.+)$", s)
                if m:
                    self._define(m.group(1), m.group(2))
                m = re.match(r"#\s*pragma\s+pack\s*\(([^)]*)\)", s)
                if m:
                    toks.append("#pack:" + m.group(1))
                continue
            toks.extend(TOKEN.findall(line))
        self.toks, self.i = toks, 0
        self._parse_top()

    def _define(self, name, expr):
        if name in self.forced:
            return
        try:
            v = eval_expr(self._expand_sizeof(expr.strip().rstrip(";")), self.constants)
            if isinstance(v, int):
                self.constants[name] = v
        except EXPR_ERRORS:
            pass

    def force_define(self, name, expr):
        """Set a constant from the command line; it takes precedence over headers."""
        self.constants.pop(name, None)
        self._define(name, expr)
        if name not in self.constants:
            sys.exit(f"--define の値を整数として評価できません: {name}={expr}")
        self.forced.add(name)

    def _expand_sizeof(self, expr):
        def size_of(m):
            words = [w for w in m.group(1).split() if w not in ("struct", "class", "union", "enum", "const")]
            if "*" in words:
                return str(self.ptr)
            if words and all(w in WORDS for w in words):
                return str(self._builtin(words).size)
            if len(words) == 1 and words[0] in self.types:
                return str(self.types[words[0]].size)
            raise KeyError(f"sizeof({m.group(1).strip()})")

        return re.sub(r"\bsizeof\s*\(([^()]*)\)", size_of, expr)

    def _safe_expand(self, expr):
        try:
            return self._expand_sizeof(expr)
        except KeyError:
            return expr

    def _dim(self, expr):
        """Return an int for a constant array length, or (mode, expr) for a variable one."""
        text = expr.strip()
        m = re.fullmatch(r"(__len|__until)\s*\((.*)\)", text, re.S)
        if m:
            return ("expr" if m.group(1) == "__len" else "until", self._safe_expand(m.group(2)))
        if text in ("__zstr", "__rest"):
            return (text[2:], "")
        try:
            return self._const(text, "配列長")
        except Unknown:
            names = re.findall(r"[A-Za-z_]\w*", text)
            visible = set().union(*self.scopes) if self.scopes else set()
            if any(n in visible or isinstance(self.types.get(n), Struct) for n in names):
                return ("expr", self._safe_expand(text))
            raise

    def _const(self, expr, what):
        try:
            v = eval_expr(self._expand_sizeof(expr), self.constants)
        except EXPR_ERRORS:
            v = None
        if not isinstance(v, int) or isinstance(v, bool):
            raise Unknown(f"{what} '{expr}' を評価できません。--define NAME=値 で補えます")
        return v

    def _parse_top(self):
        while self.peek():
            t = self.peek()
            start = self.i
            try:
                if t == "typedef":
                    self.take()
                    self._typedef()
                elif t == "namespace":
                    self.take()
                    while self.peek() not in ("{", ""):
                        self.take()
                    self.take()
                elif t == "extern" and self.peek(1).startswith('"') and self.peek(2) == "{":
                    self.i += 3
                elif t == "}":
                    self.take()
                elif t in ("struct", "class", "union", "enum"):
                    self.parse_type()
                    if self.peek() == ";":
                        self.take()
                    else:
                        self._skip()
                else:
                    self._skip()
            except (Skip, Unknown):
                self._skip()
            if self.i == start:
                self.i += 1

    def _typedef(self):
        base = self.parse_type()
        for name, t, _ in self._declarators(base):
            if isinstance(t, Struct) and not t.name:
                t.name = name
            self.types[name] = t

    def _skip(self):
        depth = 0
        while self.peek():
            t = self.peek()
            if t in "{(" and t:
                depth += 1
            elif t in ")}" and t:
                if depth == 0:
                    return
                depth -= 1
                if depth == 0 and t == "}":
                    self.take()
                    if self.peek() == ";":
                        self.take()
                    return
            elif t == ";" and depth == 0:
                self.take()
                return
            self.take()

    def _skip_attrs(self):
        packed = False
        while self.peek() in ("__attribute__", "__declspec", "alignas"):
            word = self.take()
            depth, seen = 0, []
            while True:
                t = self.take()
                seen.append(t)
                depth += (t == "(") - (t == ")")
                if depth == 0 or not t:
                    break
            if "packed" in seen or "__packed__" in seen:
                packed = True
            if word == "alignas" or "align" in seen or "aligned" in seen:
                self.warnings.append("alignas/align 指定は計算に反映していません。sizeof を実機と照合してください")
        return packed

    # ---- types
    def _builtin(self, words):
        c = Counter(words)
        uns = "unsigned" in c
        if "float" in c:
            return Prim("float", 4, "f")
        if "double" in c:
            return Prim("double", 8, "f")
        if "void" in c:
            return Prim("void", 0, "v")
        if "bool" in c or "_Bool" in c:
            return Prim("bool", 1, "b")
        if "wchar_t" in c:
            return self.types["wchar_t"]
        name = " ".join(words)
        kind = "u" if uns else "i"
        for word, size in MSVC_SIZED.items():
            if word in c:
                return Prim(name, size, kind)
        if "char" in c:
            return Prim(name, 1, kind if (uns or "signed" in c) else "c")
        if "short" in c:
            return Prim(name, 2, kind)
        if c["long"] >= 2:
            return Prim(name, 8, kind)
        if c["long"] == 1:
            return Prim(name, self.long, kind)
        return Prim(name, 4, kind)

    def parse_type(self):
        words, named = [], None
        while True:
            t = self.peek()
            if t in QUALS:
                self.take()
            elif t in ("__attribute__", "__declspec", "alignas"):
                self._skip_attrs()
            elif t in ("struct", "class", "union") and named is None:
                self.take()
                named = self._struct(t)
            elif t == "enum" and named is None:
                self.take()
                named = self._enum()
            elif t in WORDS and named is None:
                words.append(self.take())
            elif named is None and not words and IDENT.match(t or ""):
                if self.peek(1) == "::":
                    self.i += 2
                    continue
                self.take()
                if t in self.types:
                    named = self.types[t]
                elif self.peek() in ("*", "&"):
                    named = Struct(t)
                else:
                    raise Unknown(t)
            else:
                break
        if words:
            return self._builtin(words)
        if named is None:
            raise Unknown(repr(self.peek()))
        return named

    def _struct(self, keyword):
        packed = self._skip_attrs()
        name = ""
        if IDENT.match(self.peek() or ""):
            name = self.take()
        derived = self.peek() == ":"
        if derived:
            self.warnings.append(f"{name}: 継承は解析していません。基底クラス分のサイズが抜けます")
            while self.peek() not in ("{", ";", ""):
                self.take()
        if self.peek() != "{":
            return self.types.get(name) or self.forward.setdefault(name, Struct(name))
        self.take()
        # Fill in a forward declaration in place so existing typedef aliases see the definition.
        st = self.forward.pop(name, None) or Struct(name)
        st.incomplete = derived
        self.scopes.append(set())
        members = self._members(st)
        self.scopes.pop()
        self.take()
        packed = self._skip_attrs() or packed
        self._layout(st, members, 1 if packed else self.pack, keyword == "union")
        if name:
            self.types[name] = st
        return st

    def _members(self, owner):
        members = []
        while self.peek() not in ("}", ""):
            start = self.i
            try:
                self._member(members, owner)
            except Unknown as e:
                if self._is_method(start):
                    self.i = start
                else:
                    owner.incomplete = True
                    self.warnings.append(f"{owner.name or '(無名)'}: 解析できないメンバ ({e}) があり、以降のオフセットは信用できません")
                self._skip()
            except Skip:
                self._skip()
            if self.i == start:
                self.i += 1
        return members

    def _block(self, owner):
        self.expect("{")
        body = self._members(owner)
        self.expect("}")
        return body

    def _cond(self, owner):
        self.take()
        self.expect("(")
        expr = self._safe_expand(self._until(")"))
        self.expect(")")
        then = self._block(owner)
        otherwise = []
        if self.peek() == "else":
            self.take()
            otherwise = [self._cond(owner)] if self.peek() == "if" else self._block(owner)
        return Cond(expr, then, otherwise)

    def _is_method(self, start):
        """True when the statement at `start` declares a function with a return type.

        A bare `NAME(...)` is excluded because it may be a macro that expands to data.
        """
        prev = before = ""
        for t in self.toks[start:]:
            if t in (";", "{", "="):
                return False
            if t == "(":
                return bool(IDENT.match(prev)) and (bool(IDENT.match(before)) or before in (">", "*", "&"))
            before, prev = prev, t
        return False

    def _member(self, members, owner):
        t = self.peek()
        if t == ";":
            self.take()
            return
        if t == "if":
            members.append(self._cond(owner))
            return
        if t in ("public", "private", "protected") and self.peek(1) == ":":
            self.i += 2
            return
        if t == "virtual":
            self.warnings.append(f"{owner.name}: virtual あり。vtable ポインタ分のずれを考慮していません")
            owner.incomplete = True
            raise Skip("virtual")
        j = 0
        while self.peek(j) in ("inline", "constexpr", "explicit"):
            j += 1
        first = self.peek(j)
        if first in ("friend", "using", "typedef", "template", "static", "~", "operator") or (
            first == owner.name and owner.name and self.peek(j + 1) == "("
        ):
            raise Skip(first)
        base = self.parse_type()
        if self.peek() == ";":
            self.take()
            if isinstance(base, Struct) and not base.name:
                members.append(("", base, None))
            return
        declared = self._declarators(base)
        members.extend(declared)
        if self.scopes:
            self.scopes[-1].update(name for name, _, _ in declared)

    def _declarators(self, base):
        out = []
        while True:
            t = base
            while self.peek() in ("*", "&", "const", "volatile"):
                if self.take() in ("*", "&"):
                    t = Prim("ptr", self.ptr, "p")
            if self.peek() == "(" and self.peek(1) == "*":
                self.i += 2
                name = self.take()
                self.expect(")")
                self._paren()
                t = Prim("funcptr", self.ptr, "p")
            else:
                name = self.peek()
                if name == "operator":
                    raise Skip(name)
                if not IDENT.match(name or ""):
                    raise Unknown(f"宣言子の位置に {name!r}")
                self.take()
            if self.peek() == "(":
                raise Skip("function")
            dims = []
            while self.peek() == "[":
                self.take()
                dims.append(self._dim(self._until("]")))
                self.take()
            bits = None
            if self.peek() == ":":
                self.take()
                bits = self._const(self._until(",", ";"), "ビット幅")
            if self.peek() in ("=", "{"):
                self._until(",", ";")
            for n in reversed(dims):
                t = Array(t, n) if isinstance(n, int) else DynArray(t, *n)
            out.append((name, t, bits))
            if self.peek() == ",":
                self.take()
                continue
            self.expect(";")
            return out

    def _paren(self):
        depth = 0
        while self.peek():
            t = self.take()
            depth += (t == "(") - (t == ")")
            if depth == 0:
                return

    def _until(self, *ends):
        depth, parts = 0, []
        while self.peek():
            t = self.peek()
            if depth == 0 and t in ends:
                break
            depth += (t in "([{") - (t in ")]}")
            parts.append(self.take())
        return " ".join(parts)

    def _enum(self):
        if self.peek() in ("class", "struct"):
            self.take()
        name = self.take() if IDENT.match(self.peek() or "") else ""
        size, kind = 4, "e"
        if self.peek() == ":":
            self.take()
            size = self.parse_type().size
        if self.peek() != "{":
            found = self.types.get(name)
            return found if found else Prim(name or "enum", size, kind, {})
        self.take()
        names, val = {}, 0
        while self.peek() not in ("}", ""):
            item = self.take()
            if self.peek() == "=":
                self.take()
                try:
                    val = eval_expr(self._until(",", "}"), self.constants)
                except Exception:
                    pass
            names[val] = item
            self.constants[item] = val
            val += 1
            if self.peek() == ",":
                self.take()
        self.take()
        p = Prim(name or "enum", size, kind, names)
        if name:
            self.types[name] = p
        return p

    def _compile(self, members, pack):
        """Group members into static runs and items that are resolved while reading."""
        items, run = [], []

        def flush():
            if run:
                seg = Struct("")
                seg.incomplete = False
                self._layout(seg, list(run), pack, False)
                items.append(("static", seg))
                run.clear()

        for m in members:
            if isinstance(m, Cond):
                flush()
                items.append(("if", m.expr, self._compile(m.then, pack), self._compile(m.otherwise, pack)))
            elif is_dynamic(m[1]):
                flush()
                items.append(("dyn", m[0], m[1]))
            else:
                run.append(m)
        flush()
        return items

    def _layout(self, st, members, pack, is_union):
        st.incomplete = st.incomplete or any(not isinstance(m, Cond) and is_incomplete(m[1]) for m in members)
        if any(isinstance(m, Cond) or is_dynamic(m[1]) for m in members):
            if is_union:
                st.incomplete = True
                self.warnings.append(f"{st.name or '(無名)'}: 共用体の中の可変長メンバは解析できません")
                return
            # Variable-length data is normally written field by field, so members
            # are consecutive unless #pragma pack or a nested fixed struct says otherwise.
            st.dynamic = True
            st.body = self._compile(members, pack or 1)
            return
        off, end, max_align = 0, 0, 1
        unit_size, unit_off, bit = 0, 0, 0
        for name, t, bits in members:
            if t.size == 0 and isinstance(t, Struct):
                st.incomplete = True
                self.warnings.append(f"{st.name}.{name}: 型 {t.name} の定義が見つかりません")
            al = min(t.align, pack) if pack else t.align
            max_align = max(max_align, al)
            if bits is not None:
                if bits == 0:
                    unit_size = 0
                    continue
                if unit_size != t.size or bit + bits > t.size * 8:
                    if not is_union:
                        off = (off + al - 1) // al * al
                    unit_size, unit_off, bit = t.size, off, 0
                    if not is_union:
                        off += t.size
                st.fields.append(Field(name, t, unit_off, (bit, bits)))
                bit += bits
                end = max(end, unit_off + t.size)
                continue
            unit_size = 0
            if is_union:
                st.fields.append(Field(name, t, 0))
                end = max(end, t.size)
            else:
                off = (off + al - 1) // al * al
                st.fields.append(Field(name, t, off))
                off += t.size
                end = off
        st.align = max_align
        st.size = (end + max_align - 1) // max_align * max_align


# --------------------------------------------------------------------- decode


class Leaf:
    __slots__ = ("path", "offset", "size", "raw", "value", "show", "type", "kind", "bits")


def _leaf(path, offset, raw, value, show, t, kind, bits=None):
    leaf = Leaf()
    leaf.path, leaf.offset, leaf.size, leaf.raw = path, offset, len(raw), raw
    leaf.value, leaf.show, leaf.type, leaf.kind, leaf.bits = value, show, t, kind, bits
    return leaf


def _int_show(v, size):
    return f"{v} (0x{v & ((1 << (size * 8)) - 1):0{size * 2}x})"


def enum_text(names, v):
    """Return the name(s) for an enum value, or None if the value is not valid.

    An enum counts as flags only when it has at least three single-bit values and
    no others except 0 and an all-bits mask, so sequential enums stay strict.
    """
    if v in names:
        return names[v]
    bits = [k for k in names if k > 0 and k & (k - 1) == 0]
    mask = sum(bits)
    if len(bits) >= 3 and all(k in bits or k in (0, mask) for k in names) and 0 <= v and not v & ~mask:
        return "|".join(names[k] for k in sorted(bits) if v & k) or "0"
    return None


def is_dynamic(t):
    if isinstance(t, DynArray):
        return True
    if isinstance(t, Array):
        return is_dynamic(t.elem)
    return isinstance(t, Struct) and t.dynamic


def _items_incomplete(items):
    for item in items:
        if item[0] == "static" and is_incomplete(item[1]):
            return True
        if item[0] == "dyn" and is_incomplete(item[2]):
            return True
        if item[0] == "if" and (_items_incomplete(item[2]) or _items_incomplete(item[3])):
            return True
    return False


def is_incomplete(t):
    if isinstance(t, (Array, DynArray)):
        return is_incomplete(t.elem)
    if isinstance(t, Struct):
        return t.incomplete or any(is_incomplete(f.type) for f in t.fields) or _items_incomplete(t.body)
    return False


def _text(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp932", "replace")


def flatten(t, data, base, path, endian, out):
    if isinstance(t, Struct):
        for f in t.fields:
            p = f"{path}.{f.name}" if f.name else path
            if f.bits:
                raw = data[base + f.offset: base + f.offset + f.type.size]
                start, width = f.bits
                v = (int.from_bytes(raw, endian) >> start) & ((1 << width) - 1)
                out.append(_leaf(p, base + f.offset, raw, v, f"{v} (bit {start}:{width})", f.type.name, "bits", f.bits))
            else:
                flatten(f.type, data, base + f.offset, p, endian, out)
    elif isinstance(t, Array):
        e = t.elem
        raw = data[base: base + t.size]
        if isinstance(e, Prim) and e.kind == "c":
            text = _text(raw.split(b"\0", 1)[0])
            out.append(_leaf(path, base, raw, text, repr(text), t.name, "str"))
        elif isinstance(e, Prim) and e.kind == "w" and e.size == 2:
            enc = "utf-16-le" if endian == "little" else "utf-16-be"
            text = raw.decode(enc, "replace").split("\0", 1)[0]
            out.append(_leaf(path, base, raw, text, repr(text), t.name, "wstr"))
        elif isinstance(e, Prim) and e.size == 1:
            out.append(_leaf(path, base, raw, raw.hex(), hexs(raw, 24), t.name, "bytes"))
        else:
            for i in range(t.n):
                flatten(e, data, base + i * e.size, f"{path}[{i}]", endian, out)
    else:
        raw = data[base: base + t.size]
        k = t.kind
        if k == "f":
            v = struct.unpack(("<" if endian == "little" else ">") + ("f" if t.size == 4 else "d"), raw)[0]
            show = repr(v)
        elif k == "p":
            v = int.from_bytes(raw, endian)
            show = f"0x{v:0{t.size * 2}x}"
        else:
            v = int.from_bytes(raw, endian, signed=k in ("i", "c"))
            show = _int_show(v, t.size)
            if k == "e" and t.names:
                text = enum_text(t.names, v)
                show = f"{v} ({text})" if text is not None else f"{v} (未定義の enum 値)"
        out.append(_leaf(path, base, raw, v, show, t.name, k))
        if k == "e":
            out[-1].bits = t.names


class Truncated(Exception):
    """A variable-length structure cannot be followed any further."""


class Scope:
    """Resolve names from the innermost enclosing struct outward, then as full paths."""

    def __init__(self, env, scopes):
        self.env, self.scopes = env, scopes

    def _key(self, name):
        for scope in self.scopes:
            key = f"{scope}.{name}"
            if key in self.env:
                return key
        return name

    def __contains__(self, name):
        return self._key(name) in self.env

    def __getitem__(self, name):
        return self.env[self._key(name)]


class Reader:
    """Walk a variable-length struct. Corrupt lengths raise Truncated, naming the field."""

    def __init__(self, defs, data, endian, env, out):
        self.defs, self.data, self.endian, self.env, self.out = defs, data, endian, env, out

    def _need(self, pos, n, path, detail=""):
        rest = len(self.data) - pos
        if n > rest:
            raise Truncated(f"{path}: {n} バイト必要{detail}ですが、0x{pos:x} からの残りは {max(rest, 0)} バイトです")

    def _eval(self, expr, scopes, path):
        try:
            return eval_expr(expr, Scope(self.env, scopes), self.defs.types)
        except EXPR_ERRORS as err:
            raise Truncated(f"{path}: 式 '{expr}' を評価できません ({err})")

    def _flatten(self, t, pos, path):
        start = len(self.out)
        flatten(t, self.data, pos, path, self.endian, self.out)
        for leaf in self.out[start:]:
            if isinstance(leaf.value, (int, float)):
                self.env[leaf.path] = leaf.value
        return self.out[start:]

    def _static(self, t, pos, path):
        self._need(pos, t.size, path)
        self._flatten(t, pos, path)
        return pos + t.size

    def struct(self, t, pos, path, scopes):
        return self._items(t.body, pos, path, (path, *scopes))

    def _items(self, items, pos, path, scopes):
        for item in items:
            if item[0] == "static":
                pos = self._static(item[1], pos, path)
            elif item[0] == "if":
                branch = item[2] if self._eval(item[1], scopes, path) else item[3]
                pos = self._items(branch, pos, path, scopes)
            else:
                pos = self._value(item[2], pos, f"{path}.{item[1]}" if item[1] else path, scopes)
        return pos

    def _value(self, t, pos, path, scopes):
        if isinstance(t, DynArray):
            return self._array(t, pos, path, scopes)
        if isinstance(t, Array) and is_dynamic(t):
            return self._repeat(t.elem, t.n, pos, path, scopes)
        if isinstance(t, Struct) and t.dynamic:
            return self.struct(t, pos, path, scopes)
        return self._static(t, pos, path)

    def _repeat(self, elem, n, pos, path, scopes):
        for i in range(n):
            start, pos = pos, self._value(elem, pos, f"{path}[{i}]", scopes)
            if pos == start and n > 1:
                raise Truncated(f"{path}[{i}]: 要素が 0 バイトで、読み進められません")
        return pos

    def _until_end(self, t, pos, path, scopes):
        i = 0
        while t.mode == "until" or pos < len(self.data):
            item = f"{path}[{i}]"
            start, pos = pos, self._value(t.elem, pos, item, scopes)
            if pos == start:
                raise Truncated(f"{item}: 要素が 0 バイトで、読み進められません")
            if t.mode == "until" and self._eval(t.expr, (item, *scopes), item):
                break
            i += 1
        return pos

    def _zstr_count(self, width, pos, path):
        i = pos
        while True:
            if i + width > len(self.data):
                raise Truncated(f"{path}: 0x{pos:x} 以降に終端の NUL がありません")
            if not any(self.data[i: i + width]):
                return (i - pos) // width + 1
            i += width

    def _array(self, t, pos, path, scopes):
        e = t.elem
        if not is_dynamic(e) and e.size == 0:
            raise Truncated(f"{path}: 要素のサイズが 0 のため、読み進められません")
        if t.mode == "until" or (t.mode == "rest" and is_dynamic(e)):
            return self._until_end(t, pos, path, scopes)
        if t.mode == "rest":
            n = max(len(self.data) - pos, 0) // max(e.size, 1)
        elif t.mode == "zstr":
            n = self._zstr_count(e.size, pos, path)
        else:
            value = self._eval(t.expr, scopes, path)
            try:
                n = int(value)
            except (OverflowError, ValueError):
                raise Truncated(f"{path}: 長さが数値ではありません: {value}（式 {t.expr}）")
            if n < 0:
                raise Truncated(f"{path}: 長さが負の値 {n} です（式 {t.expr}）")
        if is_dynamic(e):
            return self._repeat(e, n, pos, path, scopes)
        self._need(pos, n * e.size, path, f"（長さ {n} × {e.size} バイト）")
        for leaf in self._flatten(Array(e, n), pos, path):
            if leaf.kind in ("str", "wstr"):
                leaf.kind = "l" + leaf.kind  # no NUL terminator is expected
        return pos + n * e.size


class Model:
    def __init__(self):
        self.leaves, self.gaps, self.issues, self.env, self.spans = [], [], [], {}, []
        self.dynamic = False

    def index(self):
        spans = [(x.offset, x.offset + x.size, x.path) for x in self.leaves]
        spans += [(o, o + n, f"<padding: {p} の後>") for o, n, p in self.gaps]
        spans.sort()
        self.spans = spans
        self._starts = [s[0] for s in spans]

    def paths(self, start, end):
        i = max(bisect.bisect_right(self._starts, start) - 1, 0)
        hit = []
        while i < len(self.spans) and self.spans[i][0] < max(end, start + 1):
            if self.spans[i][1] > start:
                hit.append(self.spans[i][2])
            i += 1
        return hit

    def labels(self, start, end, limit=3):
        hit = self.paths(start, end)
        text = ", ".join(hit[:limit])
        return text + (f" (他 {len(hit) - limit} 件)" if len(hit) > limit else "")


LAYOUT_ITEM = re.compile(r"^(\w+)(?:\[(.+)\]|(\*))?(?:@(.+))?$")


def split_layout(s):
    parts, depth, cur = [], 0, ""
    for ch in s:
        depth += (ch == "[") - (ch == "]")
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    return [p.strip() for p in parts + [cur] if p.strip()]


def decode(defs, data, layout, endian):
    m = Model()
    m.env = {"FILESIZE": len(data), **defs.constants}
    pos, stopped = 0, False

    def ev(e):
        try:
            return eval_expr(e, m.env, defs.types)
        except EXPR_ERRORS as err:
            sys.exit(f"layout の式 '{e}' を評価できません: {err}")

    def whole(e):
        try:
            return int(ev(e))
        except (OverflowError, ValueError):
            return None

    for item in split_layout(layout):
        g = LAYOUT_ITEM.match(item)
        if not g:
            sys.exit(f"layout の書式が不正です: {item}")
        name, count, star, at = g.groups()
        if name not in defs.types:
            structs = ", ".join(k for k, v in defs.types.items() if isinstance(v, Struct))
            sys.exit(f"型 {name} が定義にありません。見つかった構造体: {structs or 'なし'}")
        t = defs.types[name]
        if stopped:
            m.issues.append(f"{item}: 前の項目が途切れたため未解析")
            continue
        if at:
            pos = whole(at)
            if pos is None or not 0 <= pos <= len(data):
                m.issues.append(f"{item}: 開始位置がファイルの範囲外です (値 {ev(at)}, ファイルサイズ {len(data)})")
                stopped = True
                continue
        n = None if star else (whole(count) if count else 1)
        if not star and (n is None or n < 0):
            m.issues.append(f"{item}: 個数が負の値か、数値ではありません (値 {ev(count)})")
            stopped = True
            continue
        idx = 0
        while (n is None and pos < len(data)) or (n is not None and idx < n):
            path = name if (count is None and not star) else f"{name}[{idx}]"
            inst = []
            if is_dynamic(t):
                m.dynamic = True
                try:
                    end = Reader(defs, data, endian, m.env, inst).struct(t, pos, path, ())
                except Truncated as err:
                    m.issues.append(str(err))
                    stopped, end = True, None
                if end == pos:
                    m.issues.append(f"{path}: 0 バイトで終わり、読み進められません")
                    stopped = True
            else:
                if t.size <= 0:
                    sys.exit(f"型 {name} のサイズが 0 です")
                if pos + t.size > len(data):
                    want = "末尾まで" if n is None else f"{n} 個"
                    m.issues.append(
                        f"{name}: {want}の指定に対し {idx} 個目で途切れ "
                        f"(0x{pos:x} から {t.size} バイト必要、残り {max(len(data) - pos, 0)} バイト)"
                    )
                    stopped = True
                    break
                flatten(t, data, pos, path, endian, inst)
                end = pos + t.size
            m.leaves.extend(inst)
            cursor, prev = pos, path
            for leaf in sorted(inst, key=lambda x: x.offset):
                if leaf.offset > cursor:
                    m.gaps.append((cursor, leaf.offset - cursor, prev))
                if leaf.offset + leaf.size >= cursor:
                    cursor, prev = leaf.offset + leaf.size, leaf.path
            if end is not None and cursor < end:
                m.gaps.append((cursor, end - cursor, prev))
            for leaf in inst:
                if isinstance(leaf.value, (int, float)):
                    m.env[leaf.path] = leaf.value
            if stopped:
                break
            pos = end
            idx += 1
    if not stopped and pos < len(data):
        m.issues.append(f"レイアウト終端 0x{pos:x} の後に {len(data) - pos} バイト余り")
    m.index()
    return m


def load_defs(args):
    if not getattr(args, "defs", None):
        return None
    if not args.layout:
        sys.exit("--defs を使うときは --layout も指定してください")
    d = Defs(args.ptr, args.long, args.pack)
    for item in args.define or []:
        name, sep, value = item.partition("=")
        if not sep or not name.strip():
            sys.exit(f"--define は NAME=値 の形で指定してください: {item}")
        d.force_define(name.strip(), value)
    for path in args.defs:
        with open(path, encoding="utf-8", errors="replace") as f:
            d.feed(f.read())
    for w in dict.fromkeys(d.warnings):
        print(f"[警告] {w}")
    for item in split_layout(args.layout):
        g = LAYOUT_ITEM.match(item)
        t = d.types.get(g.group(1)) if g else None
        if t is not None and is_incomplete(t):
            d.layout_warnings.append(f"レイアウト対象 {g.group(1)} は完全には解析できていません。フィールド位置は信用できません")
    for w in dict.fromkeys(d.layout_warnings):
        print(f"[警告] {w}")
    return d


def read(path):
    with open(path, "rb") as f:
        return f.read()


# ------------------------------------------------------------------ alignment


def _anchors(a, b, k=16):
    if len(a) < k or len(b) < k:
        return []
    step = max(1, len(a) // 1_000_000)
    seen = {}
    for i in range(0, len(a) - k + 1, step):
        km = a[i: i + k]
        seen[km] = -1 if km in seen else i
    hits = {}
    for j in range(len(b) - k + 1):
        km = b[j: j + k]
        if seen.get(km, -1) >= 0:
            hits[km] = -1 if km in hits else j
    pairs = sorted((seen[km], j) for km, j in hits.items() if j >= 0)
    tails, idx, prev = [], [], [-1] * len(pairs)
    for n, (_, j) in enumerate(pairs):
        p = bisect.bisect_left(tails, j)
        if p == len(tails):
            tails.append(j)
            idx.append(n)
        else:
            tails[p], idx[p] = j, n
        prev[n] = idx[p - 1] if p else -1
    out, n = [], idx[-1] if idx else -1
    while n >= 0:
        out.append(pairs[n])
        n = prev[n]
    return out[::-1]


def positional_ops(a, a0, b, b0, n):
    ops, start = [], None
    for i, (x, y) in enumerate(zip(a[a0: a0 + n], b[b0: b0 + n])):
        if x != y:
            if start is None:
                start = i
        elif start is not None:
            ops.append(("replace", a0 + start, a0 + i, b0 + start, b0 + i))
            start = None
    if start is not None:
        ops.append(("replace", a0 + start, a0 + n, b0 + start, b0 + n))
    return ops


def _gap(a, a0, a1, b, b0, b1, ops):
    la, lb = a1 - a0, b1 - b0
    if la == lb:
        ops.extend(positional_ops(a, a0, b, b0, la))
        return
    p = 0
    while p < min(la, lb) and a[a0 + p] == b[b0 + p]:
        p += 1
    s = 0
    while s < min(la, lb) - p and a[a1 - 1 - s] == b[b1 - 1 - s]:
        s += 1
    a0, b0, a1, b1 = a0 + p, b0 + p, a1 - s, b1 - s
    la, lb = a1 - a0, b1 - b0
    if la == 0 or lb == 0:
        ops.append(("insert" if la == 0 else "delete", a0, a1, b0, b1))
    elif max(la, lb) <= 8192:
        sm = SequenceMatcher(None, a[a0:a1], b[b0:b1], autojunk=False)
        for tag, i0, i1, j0, j1 in sm.get_opcodes():
            if tag != "equal":
                ops.append((tag, a0 + i0, a0 + i1, b0 + j0, b0 + j1))
    else:
        ops.append(("replace", a0, a1, b0, b1))


def align(a, b):
    ops, ai, bi = [], 0, 0
    for x, y in _anchors(a, b):
        if x < ai or y < bi:
            continue
        _gap(a, ai, x, b, bi, y, ops)
        while x < len(a) and y < len(b) and a[x] == b[y]:
            x += 1
            y += 1
        ai, bi = x, y
    _gap(a, ai, len(a), b, bi, len(b), ops)
    if len(a) == len(b):
        pos = positional_ops(a, 0, b, 0, len(a))
        if sum(o[2] - o[1] for o in pos) <= sum(o[2] - o[1] for o in ops):
            ops = pos
    return merge(ops)


def merge(ops, gap=4):
    out = []
    for op in ops:
        if out:
            t, a0, a1, b0, b1 = out[-1]
            da, db = op[1] - a1, op[3] - b1
            if da == db and da < gap:
                out[-1] = ("replace", a0, op[2], b0, op[4])
                continue
        out.append(op)
    return out


# -------------------------------------------------------------------- commands


MAGIC = [
    (b"\x89PNG", "PNG"), (b"PK\x03\x04", "ZIP"), (b"\x1f\x8b", "gzip"), (b"SQLite format 3", "SQLite"),
    (b"\x7fELF", "ELF"), (b"MZ", "PE/DOS"), (b"\x78\x9c", "zlib"), (b"\x78\xda", "zlib"), (b"BZh", "bzip2"),
    (b"7z\xbc\xaf", "7z"), (b"\xfd7zXZ", "xz"), (b"\x28\xb5\x2f\xfd", "zstd"), (b"\xff\xd8\xff", "JPEG"),
    (b"%PDF", "PDF"), (b"{", "JSON 風テキスト"), (b"<", "XML 風テキスト"),
]


def entropy(b):
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in Counter(b).values())


def periods(d):
    s = d[:32768]
    n = len(s)
    if n < 64:
        return []
    scores = {}
    for p in range(2, min(1024, n // 4) + 1):
        scores[p] = sum(1 for x, y in zip(s, s[p:]) if x == y and x) / (n - p)
    med = sorted(scores.values())[len(scores) // 2]
    best = []
    for p, sc in sorted(scores.items(), key=lambda kv: -kv[1]):
        if sc < 0.15 or sc < med * 2:
            break
        if not any(p % q == 0 and sc <= s_ * 1.1 for q, s_ in best):
            best.append((p, sc))
        if len(best) == 3:
            break
    return best


def cmd_overview(args):
    d = read(args.file)
    print(f"size   : {len(d)} (0x{len(d):x})")
    print(f"sha256 : {hashlib.sha256(d).hexdigest()}")
    print(f"先頭   : {hexs(d, 32)}  |{ascii_of(d, 32)}|")
    print(f"末尾   : {hexs(d[-16:], 16)}  |{ascii_of(d[-16:], 16)}|")
    for sig, name in MAGIC:
        if d.startswith(sig):
            print(f"形式候補: {name}")
            break
    if not d:
        return
    size = max(4096 if len(d) >= 4096 * 4 else 256, len(d) // args.max)
    print(f"\nエントロピー (ブロック {size} バイト。近い値は連結):")
    rows = []
    for i in range(0, len(d), size):
        e = entropy(d[i: i + size])
        if rows and abs(rows[-1][2] - e) < 0.5:
            rows[-1][1] = i + size
        else:
            rows.append([i, i + size, e])
    for s, e, v in rows[: args.max]:
        note = " ← 圧縮/暗号の可能性" if v >= 7.5 else (" ← ほぼ一定" if v < 0.5 else "")
        print(f"  0x{s:08x}-0x{min(e, len(d)):08x}  {v:4.2f}{note}")
    print("\n同一バイトの連続 (16 バイト以上、長い順):")
    runs = [(m.start(), len(m.group()), m.group()[0]) for m in re.finditer(rb"(.)\1{15,}", d, re.S)]
    for off, n, b in sorted(runs, key=lambda r: -r[1])[: args.max]:
        name = fill_name(bytes([b, b]))
        print(f"  0x{off:08x} len={n} byte={b:02x}" + (f"  {name}" if name else ""))
    if len(runs) > args.max:
        print(f"  … 他 {len(runs) - args.max} 件")
    words = [m.group(0) for m in re.finditer(rb"\xee\xfe\xee\xfe|\x0d\xf0\xad\xba|\xef\xbe\xad\xde", d)]
    if words:
        print(f"\nデバッグ用 4 バイトパターン: {len(words)} 箇所")
    crlf, lf = d.count(b"\r\n"), d.count(b"\n")
    if crlf and crlf == lf and lf > 2:
        print(f"\n注意: 0A がすべて 0D 0A の形 ({crlf} 箇所)。テキストモード書き込みの疑い")
    per = periods(d)
    if per:
        print("\nレコード長の候補 (先頭 32KiB の自己相関):")
        for p, sc in per:
            print(f"  {p} バイト (0x{p:x}) 一致率 {sc:.2f}")
    print("\n文字列 (ASCII / UTF-16LE):")
    found = [(m.start(), m.group().decode()) for m in re.finditer(rb"[\x20-\x7e]{6,}", d)]
    found += [(m.start(), m.group().decode("utf-16-le")) for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", d)]
    found.sort()
    for off, s in found[: args.max]:
        print(f"  0x{off:08x} {s[:80]!r}")
    if len(found) > args.max:
        print(f"  … 他 {len(found) - args.max} 件")


def cmd_view(args):
    at, n = int(args.at, 0), int(args.len, 0)
    for path in args.files:
        d = read(path)
        print(f"--- {path} (size {len(d)})")
        for i in range(at, min(at + n, len(d)), 16):
            row = d[i: i + 16]
            print(f"{i:08x}  {row.hex(' '):<47}  |{ascii_of(row, 16)}|")


def cmd_decode(args):
    defs = load_defs(args)
    if not defs:
        sys.exit("--defs と --layout が必要です")
    d = read(args.file)
    for item in split_layout(args.layout):
        name = LAYOUT_ITEM.match(item).group(1)
        if name in defs.types:
            t = defs.types[name]
            print(f"sizeof({name}) = 可変長" if is_dynamic(t) else f"sizeof({name}) = {t.size} (align {t.align})")
    m = decode(defs, d, args.layout, args.endian)
    shown = [x for x in m.leaves if not args.grep or re.search(args.grep, x.path)]
    for x in shown[: args.max]:
        print(f"0x{x.offset:08x} +{x.size:<4} {x.path:<36} {x.type:<14} {x.show}")
    if len(shown) > args.max:
        print(f"… 他 {len(shown) - args.max} フィールドは省略 (--max / --grep)")
    report_issues(m, d)


def report_issues(m, d):
    for i in m.issues:
        print(f"[構造] {i}")


def plausibility(m, d):
    found = []
    for x in m.leaves:
        if x.kind == "f" and not math.isfinite(x.value):
            found.append((x, "NaN/Inf"))
        elif x.kind == "f" and abs(x.value) > 1e30:
            found.append((x, "異常に大きい浮動小数"))
        elif x.kind == "b" and x.value not in (0, 1):
            found.append((x, "bool が 0/1 以外"))
        elif x.kind == "e" and x.bits and enum_text(x.bits, x.value) is None:
            found.append((x, "未定義の enum 値"))
        elif x.kind == "p" and x.value:
            found.append((x, "ポインタの実値を保存している（再読込では無効）"))
        elif x.kind in ("str", "wstr"):
            cut = x.raw.find(b"\0")
            if cut < 0:
                found.append((x, "NUL 終端がない"))
            elif any(x.raw[cut:]):
                found.append((x, "NUL より後に非ゼロのごみ（未初期化/前回値の残留疑い）"))
        name = fill_name(x.raw) if x.kind != "bits" else None
        if name and "ゼロ" not in name and "FF" not in name:
            found.append((x, f"値が {name}"))
    return found


def field_map(m):
    return {x.path: x for x in m.leaves}


def load_mask(path):
    if not path:
        return lambda op: False
    with open(path, encoding="utf-8") as f:
        mask = json.load(f)["noise"]
    starts = [r[0] for r in mask]

    def is_noise(op):
        # A positional noise mask cannot justify hiding insertions/deletions
        # or differences whose coordinates shifted during alignment.
        if op[0] != "replace" or op[1:3] != op[3:5]:
            return False
        i = bisect.bisect_right(starts, op[1]) - 1
        return op[2] > op[1] and i >= 0 and mask[i][1] >= op[2]

    return is_noise


def observations(a, b, regions):
    total, shifts, crlf, notes = 0, [], 0, []
    for t, a0, a1, b0, b1 in regions:
        delta = (b1 - b0) - (a1 - a0)
        if delta:
            total += delta
            shifts.append((a1, delta, total))
        if t == "insert" and b[b0:b1] == b"\r" and a[a0: a0 + 1] == b"\n":
            crlf += 1
    if crlf:
        notes.append(f"0A の前に 0D が挿入された箇所が {crlf} 件。テキストモード書き込みの疑いが強い")
    n = min(len(a), len(b))
    if regions and len(a) != len(b) and a[:n] == b[:n]:
        side = "B" if len(b) < len(a) else "A"
        bounds = [s for s in (512, 4096, 65536) if n % s == 0]
        notes.append(f"{side} はもう一方の先頭 {n} バイトと一致して途切れている"
                     + (f"（{bounds[-1]} バイト境界。flush 漏れ/書き込み中断の疑い）" if bounds else ""))
    return shifts, notes


def cmd_diff(args):
    a, b = read(args.a), read(args.b)
    defs = load_defs(args)
    ma = decode(defs, a, args.layout, args.endian) if defs else None
    mb = decode(defs, b, args.layout, args.endian) if defs else None
    print(f"A: {args.a} size={len(a)}")
    print(f"B: {args.b} size={len(b)}  (差 {len(b) - len(a):+d})")
    if a == b:
        print("完全に一致")
        return
    all_regions = align(a, b)
    is_noise = load_mask(args.mask)
    regions = [r for r in all_regions if not is_noise(r)]
    hidden = len(all_regions) - len(regions)
    print(f"差分領域: {len(regions)} 件" + (f" (ノイズとして {hidden} 件を除外)" if hidden else ""))
    if regions:
        print(f"最初の差分: A@0x{regions[0][1]:x}")
    shifts, notes = observations(a, b, all_regions)
    if shifts:
        print("ずれの発生点:")
        for off, delta, cum in shifts[: args.max]:
            print(f"  A@0x{off:x} で {delta:+d} バイト → 以降の累計ずれ {cum:+d}")
        if len(shifts) > args.max:
            print(f"  … 他 {len(shifts) - args.max} 件")
    for note in notes:
        print(f"注意: {note}")
    print()
    for i, (t, a0, a1, b0, b1) in enumerate(regions[: args.max], 1):
        ra, rb = a[a0:a1], b[b0:b1]
        print(f"[{i}] {t} A@0x{a0:x}+{a1 - a0} B@0x{b0:x}+{b1 - b0}")
        if ma:
            label = ma.labels(a0, a1) or "(レイアウト外)"
            print(f"    フィールド: {label}")
        if ra:
            print(f"    A: {hexs(ra)}  |{ascii_of(ra)}|")
        if rb:
            print(f"    B: {hexs(rb)}  |{ascii_of(rb)}|")
        for h in hints(ra, rb):
            print(f"    → {h}")
    if len(regions) > args.max:
        print(f"… 他 {len(regions) - args.max} 領域は省略 (--max)")
    if ma:
        print("\nフィールド単位の差分:")
        report_issues(ma, a)
        report_issues(mb, b)
        fa, fb = field_map(ma), field_map(mb)
        changed = [p for p in fa if p in fb and fa[p].raw != fb[p].raw]
        only_a = [p for p in fa if p not in fb]
        only_b = [p for p in fb if p not in fa]
        for p in changed[: args.max]:
            print(f"  0x{fa[p].offset:08x} {p}: {fa[p].show} → {fb[p].show}")
        if len(changed) > args.max:
            print(f"  … 他 {len(changed) - args.max} 件")
        if only_a or only_b:
            print(f"  A のみのフィールド {len(only_a)} 件 / B のみ {len(only_b)} 件")
        if shifts and not ma.dynamic:
            print("  ※ ずれの発生点より後のフィールド差分は、ずれの結果である可能性が高い")


def _ranges(flags):
    out, start = [], None
    for i, v in enumerate(flags):
        if v and start is None:
            start = i
        elif not v and start is not None:
            out.append([start, i])
            start = None
    if start is not None:
        out.append([start, len(flags)])
    return out


def cmd_multi(args):
    goods = [read(p) for p in args.good]
    bads = [read(p) for p in args.bad]
    print("サイズ: " + ", ".join(f"good{i}={len(d)}" for i, d in enumerate(goods))
          + ", " + ", ".join(f"bad{i}={len(d)}" for i, d in enumerate(bads)))
    if len(goods) < 2:
        print("[警告] 正常ファイルが 1 個なのでノイズを除外できません。2 個以上あると精度が上がります")
    sizes = {len(d) for d in goods + bads}
    n = min(sizes)
    if len(sizes) > 1:
        print(f"[警告] サイズが異なるため、バイト比較は先頭 {n} バイトの同位置比較です。可変長なら --defs/--layout か diff を使ってください")
    if not n:
        return
    strong, weak, noise = bytearray(n), bytearray(n), bytearray(n)
    for i, column in enumerate(zip(*goods, *bads)):
        gs, bs = column[: len(goods)], column[len(goods):]
        lo, hi = min(gs), max(gs)
        if lo != hi:
            noise[i] = 1
            if any(v < lo or v > hi for v in bs):
                weak[i] = 1
        elif any(v != lo for v in bs):
            strong[i] = 1
    print(f"正常同士で変動するバイト (ノイズ): {sum(noise)} / {n}")
    defs = load_defs(args)
    models, weak_fields = None, []
    if defs:
        mg = [decode(defs, d, args.layout, args.endian) for d in goods]
        mb = [decode(defs, d, args.layout, args.endian) for d in bads]
        models = mg[0]
        weak_fields = field_multi(args, mg, mb)
    if args.save_mask:
        # Keep suspicious values visible in downstream diff/report output, including
        # field values that look unremarkable when compared one byte at a time.
        mask_noise = bytearray(v and not weak[i] for i, v in enumerate(noise))
        for leaf in weak_fields:
            for i in range(leaf.offset, min(leaf.offset + leaf.size, n)):
                mask_noise[i] = 0
        if len(sizes) > 1:
            # Same-offset comparison means nothing once the files have different shapes.
            mask_noise = bytearray(n)
            print("[警告] サイズが異なるファイルからは位置ベースのマスクを作れないため、空のマスクを保存します")
        with open(args.save_mask, "w", encoding="utf-8") as f:
            json.dump({"noise": _ranges(mask_noise)}, f)
        print(f"ノイズマスクを保存: {args.save_mask}")

    if defs and len(sizes) > 1:
        print("\nサイズが異なるため、バイト単位の比較は省略しました。上のフィールド比較を見てください")
        return

    def show(title, flags):
        rs = merge([("replace", s, e, s, e) for s, e in _ranges(flags)])
        print(f"\n{title}: {len(rs)} 領域")
        for _, s, e, _, _ in rs[: args.max]:
            label = f"  [{models.labels(s, e)}]" if models else ""
            print(f"  0x{s:08x}+{e - s}{label}")
            print(f"    good: {hexs(goods[0][s:e])}")
            for j, d in enumerate(bads):
                print(f"    bad{j}: {hexs(d[s:e])}")
            for h in hints(goods[0][s:e], bads[0][s:e], ("good", "bad")):
                print(f"    → {h}")
        if len(rs) > args.max:
            print(f"  … 他 {len(rs) - args.max} 領域は省略 (--max)")

    show("【強】正常では常に同じなのに不正で異なるバイト", strong)
    show("【弱】正常でも変動するが、不正は正常の範囲外のバイト", weak)


def field_multi(args, mg, mb):
    gmaps, bmaps = [field_map(m) for m in mg], [field_map(m) for m in mb]
    for i, m in enumerate(mg):
        for s in m.issues:
            print(f"[構造 good{i}] {s}")
    for i, m in enumerate(mb):
        for s in m.issues:
            print(f"[構造 bad{i}] {s}")
    strong, weak, missing, noise = [], [], [], 0
    for path in dict.fromkeys(p for m in gmaps + bmaps for p in m):
        gs = [m[path] for m in gmaps if path in m]
        bs = [m[path] for m in bmaps if path in m]
        if len(gs) < len(gmaps) or len(bs) < len(bmaps):
            missing.append(path)
            continue
        graw = {x.raw for x in gs}
        out = [x for x in bs if x.raw not in graw]
        if len(graw) == 1:
            if out:
                strong.append((gs[0], bs, len(out) == len(bs) and len({x.raw for x in out}) == 1))
        else:
            noise += 1
            if out:
                # Strings and byte arrays have no meaningful range: an unseen value is enough.
                numeric = all(isinstance(x.value, (int, float)) for x in gs + out)
                vals = [x.value for x in gs] if numeric else []
                if not numeric or any(not min(vals) <= x.value <= max(vals) for x in out):
                    weak.append((gs[0], bs, False))
    print(f"\nフィールド比較: 正常同士で変動 (ノイズ) {noise} 件")

    def show(title, rows):
        print(f"{title}: {len(rows)} 件")
        for g, bs, agree in rows[: args.max]:
            mark = " [不正ファイルすべてで同じ値]" if agree and len(bs) > 1 else ""
            print(f"  0x{g.offset:08x} {g.path}: good={g.show} bad={', '.join(b.show for b in bs)}{mark}")
        if len(rows) > args.max:
            print(f"  … 他 {len(rows) - args.max} 件は省略 (--max)")

    show("【強】正常では一定なのに不正で異なるフィールド", strong)
    show("【弱】正常でも変動するが、不正は正常にない値（数値は範囲外）のフィールド", weak)
    if missing:
        print(f"一部のファイルにしかないフィールド: {len(missing)} 件 (例: {', '.join(missing[:5])})")
    return [x for g, bs, _ in weak for x in (g, *bs)]


# ---- integrity


def _crc16(data, poly, init, refl):
    crc = init
    if refl:
        for b in data:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
    else:
        for b in data:
            crc ^= b << 8
            for _ in range(8):
                crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
    return crc ^ 0xFFFFFFFF


def _fnv1a(data):
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def _fletcher16(data):
    s1 = s2 = 0
    for b in data:
        s1 = (s1 + b) % 255
        s2 = (s2 + s1) % 255
    return (s2 << 8) | s1


def _sum32w(data):
    n = len(data) // 4
    return sum(struct.unpack(f"<{n}I", data[: n * 4])) & 0xFFFFFFFF


# name: (width, function, is_fast)
ALGOS = {
    "crc32": (4, zlib.crc32, True),
    "adler32": (4, zlib.adler32, True),
    "sum32(bytes)": (4, lambda d: sum(d) & 0xFFFFFFFF, True),
    "sum32(u32le)": (4, _sum32w, True),
    "sum16(bytes)": (2, lambda d: sum(d) & 0xFFFF, True),
    "crc32c": (4, _crc32c, False),
    "fnv1a32": (4, _fnv1a, False),
    "fletcher16": (2, _fletcher16, False),
    "crc16-ccitt": (2, lambda d: _crc16(d, 0x1021, 0xFFFF, False), False),
    "crc16-xmodem": (2, lambda d: _crc16(d, 0x1021, 0, False), False),
    "crc16-modbus": (2, lambda d: _crc16(d, 0xA001, 0xFFFF, True), False),
    "crc16-arc": (2, lambda d: _crc16(d, 0xA001, 0, True), False),
}
PY_LIMIT = 256 * 1024


def _slot(size, where, w):
    return size - w if where == "tail" else where


def _region(d, pos, w, where, rng):
    """rng: an int start offset, "before" (everything ahead of the field) or "zeroed"."""
    if rng == "before":
        return d[:pos]
    if rng == "zeroed":
        return d[:pos] + b"\0" * w + d[pos + w:]
    return d[rng: pos] if where == "tail" else d[rng:]


def _ranges_for(name, where, pos, w, size, fast, head):
    # Wide start-offset search covers bodies that begin after padding or a longer
    # header. It stays 32-bit only: at 16 bits it would produce chance matches.
    wide = w == 4 and (fast or size <= 16 * 1024)
    if where == "tail":
        starts = range(0, head, 4) if wide else [0]
    else:
        starts = range((pos + w + 3) // 4 * 4, head + 4, 4) if wide else [pos + w]
    out = [s for s in starts if size - s >= 8]
    if where != "tail" and pos >= 8:
        out.append("before")
    if size <= 1024 * 1024 and (fast or size <= 16 * 1024):
        out.append("zeroed")
    return out


def checksum_search(d):
    size, found, cache = len(d), set(), {}
    if size < 16 or size > 64 * 1024 * 1024:
        return found
    head = min(size - 2, 128 if size <= 1024 * 1024 else 32)
    for name, (w, fn, fast) in ALGOS.items():
        if not fast and size > PY_LIMIT:
            continue
        for where in list(range(0, head, w)) + ["tail"]:
            pos = _slot(size, where, w)
            if pos < 0 or pos + w > size:
                continue
            raw = d[pos: pos + w]
            if raw in (b"\0" * w, b"\xff" * w):
                continue
            for rng in _ranges_for(name, where, pos, w, size, fast, head):
                key = (name, rng, where == "tail") if isinstance(rng, int) else (name, rng, pos)
                if key not in cache:
                    cache[key] = fn(_region(d, pos, w, where, rng))
                for endian in ("little", "big"):
                    if int.from_bytes(raw, endian) == cache[key]:
                        found.add((name, where, rng, endian))
    return found


def checksum_holds(d, hyp):
    name, where, rng, endian = hyp
    w, fn, _ = ALGOS[name]
    pos = _slot(len(d), where, w)
    if pos < 0 or pos + w > len(d):
        return False
    return int.from_bytes(d[pos: pos + w], endian) == fn(_region(d, pos, w, where, rng))


def _describe_range(rng, where):
    if rng == "before":
        return "先頭からこのフィールドの直前まで"
    if rng == "zeroed":
        return "ファイル全体（このフィールドを 0 とみなす）"
    return f"0x{rng:x} から" + ("このフィールドの直前まで" if where == "tail" else "末尾まで")


def length_search(d):
    found, size = set(), len(d)
    for w in (2, 4, 8):
        for pos in range(0, min(64, size - w + 1), w):
            for endian in ("little", "big"):
                v = int.from_bytes(d[pos: pos + w], endian)
                if v < 16:
                    continue
                for rel, target in (("全体長", size), ("この位置から末尾", size - pos), ("このフィールドの直後から末尾", size - pos - w)):
                    if v == target:
                        found.add((pos, w, endian, rel))
    return found


def length_holds(d, hyp):
    pos, w, endian, rel = hyp
    if pos + w > len(d):
        return False
    target = {"全体長": len(d), "この位置から末尾": len(d) - pos, "このフィールドの直後から末尾": len(d) - pos - w}[rel]
    return int.from_bytes(d[pos: pos + w], endian) == target


def cmd_check(args):
    files = [(p, read(p)) for p in args.files]
    defs = load_defs(args)
    for path, d in files:
        print(f"=== {path} (size {len(d)})")
        if not defs:
            continue
        m = decode(defs, d, args.layout, args.endian)
        report_issues(m, d)
        for x, why in plausibility(m, d)[: args.max]:
            print(f"[値] 0x{x.offset:08x} {x.path} = {x.show}: {why}")
        dirty = [(o, n, p) for o, n, p in m.gaps if any(d[o: o + n])]
        if dirty:
            print(f"[padding] 非ゼロの padding が {len(dirty)} 箇所（構造体の未初期化のまま書き出している疑い）")
            for o, n, p in dirty[: args.max]:
                print(f"  0x{o:08x}+{n} {p} の後: {hexs(d[o: o + n])}")
        for expr in args.expect or []:
            try:
                print(f"[expect] {'OK' if eval_expr(expr, m.env, defs.types) else 'NG'}: {expr}")
            except KeyError as e:
                print(f"[expect] 評価不能 (フィールド {e} がありません): {expr}")
    if any(not fast and len(d) > PY_LIMIT for _, (_, _, fast) in ALGOS.items() for _, d in files):
        print(f"\n[注意] {PY_LIMIT} バイト超のファイルでは一部のアルゴリズムを省略しました")
    names = [p for p, _ in files]

    def table(title, hyps, holds, describe):
        print(f"\n{title}: {len(hyps)} 件")
        rows = sorted(hyps, key=lambda h: -sum(holds(d, h) for _, d in files))
        for h in rows[: args.max]:
            marks = "  ".join(f"{n.replace(chr(92), '/').rsplit('/', 1)[-1]}={'OK' if holds(d, h) else 'NG'}"
                              for n, (_, d) in zip(names, files))
            print(f"  {describe(h)}\n    {marks}")
        if len(rows) > args.max:
            print(f"  … 他 {len(rows) - args.max} 件は省略 (--max)")

    hyps = set().union(*(checksum_search(d) for _, d in files))
    table("チェックサム仮説（1 ファイルでも成立したもの）", hyps, checksum_holds,
          lambda h: f"{h[0]} 格納位置={'末尾' if h[1] == 'tail' else hex(h[1])} 範囲={_describe_range(h[2], h[1])} {h[3]}")
    lens = set().union(*(length_search(d) for _, d in files))
    table("長さフィールド仮説", lens, length_holds,
          lambda h: f"0x{h[0]:x} の u{h[1] * 8} {h[2]} = {h[3]}")


# ---- visual report


REPORT_CSS = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#1f2328;--dim:#667;--line:#dfe1e4;
--bug:#c62828;--bug-bg:#fbd5d5;--suspect:#b45f00;--suspect-bg:#ffe3b8;--info:#1760b0;--info-bg:#d5e6fa;
--auto:#6a4fb3;--auto-bg:#e6defa;--noise-bg:#e5e6e8}
@media (prefers-color-scheme:dark){:root{--bg:#16181c;--card:#1f2228;--ink:#e8eaed;--dim:#9aa3ad;--line:#343840;
--bug:#ff8a80;--bug-bg:#6b1f1f;--suspect:#ffb74d;--suspect-bg:#5f3d0a;--info:#82b8f5;--info-bg:#173a63;
--auto:#b9a3f5;--auto-bg:#3a2c66;--noise-bg:#33363c}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 system-ui,"Segoe UI","Yu Gothic UI",sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0}
.sub{color:var(--dim);font-size:13px}
.summary{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--bug);border-radius:6px;padding:12px 16px;margin:16px 0}
.stats{display:flex;flex-wrap:wrap;gap:8px 28px;margin:14px 0}.stats b{font-size:18px;display:block}
.stats div{font-size:12px;color:var(--dim)}.stats b{color:var(--ink)}
.obs{margin:8px 0;padding-left:20px}
.map{position:relative;height:26px;background:var(--card);border:1px solid var(--line);border-radius:4px;margin:6px 0 2px;overflow:hidden}
.map a,.map i{position:absolute;top:0;bottom:0;min-width:3px}
.map i{background:var(--noise-bg)}
.scale{display:flex;justify-content:space-between;font:12px ui-monospace,Consolas,monospace;color:var(--dim)}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:13px;margin:12px 0 20px}
.legend span{display:inline-flex;align-items:center;gap:6px}
.swatch{display:inline-block;width:14px;height:14px;border-radius:3px}
.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px 16px;margin:14px 0;scroll-margin-top:12px}
.head{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px}
.badge{font-size:12px;font-weight:700;padding:1px 8px;border-radius:10px;white-space:nowrap}
.bug{--c:var(--bug);--b:var(--bug-bg)}.suspect{--c:var(--suspect);--b:var(--suspect-bg)}
.info{--c:var(--info);--b:var(--info-bg)}.auto{--c:var(--auto);--b:var(--auto-bg)}
.badge,.map a,.swatch.lv{background:var(--b);color:var(--c)}.map a{background:var(--c)}
.pos{font:13px ui-monospace,Consolas,monospace;color:var(--dim)}
.note{margin:8px 0 0}.note b{color:var(--c)}
.panels{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,500px),1fr));gap:12px;margin-top:12px}
.panel{min-width:0}.panel h3{font-size:13px;margin:0 0 4px;color:var(--dim);font-weight:600}
.hex{font:13px/1.65 ui-monospace,Consolas,monospace;overflow-x:auto;white-space:nowrap;border:1px solid var(--line);border-radius:4px;padding:6px 8px}
.o{color:var(--dim);margin-right:12px}.s{margin-left:12px;border-left:1px solid var(--line);padding-left:10px}
.hex u{text-decoration:none;display:inline-block;width:2.5ch;text-align:center;border-radius:2px;margin-right:1px}
.hex u.g{margin-left:1ch}.s u{width:1ch;margin:0}
.x{background:var(--b);color:var(--c);font-weight:700;outline:1.5px solid var(--c);outline-offset:-1.5px}
.d{background:var(--auto-bg)}.n{background:var(--noise-bg)}
.c{box-shadow:inset 2px 0 0 var(--bug)}
table{border-collapse:collapse;font-size:13px;margin-top:10px;width:100%}
th,td{border-bottom:1px solid var(--line);padding:3px 8px;text-align:left;overflow-wrap:anywhere}
th{color:var(--dim);font-weight:600}td.m{font-family:ui-monospace,Consolas,monospace}
ul.h{margin:8px 0 0;padding-left:20px;font-size:13px;color:var(--dim)}
.more{color:var(--dim);font-size:13px;margin-top:8px}
"""
LEVELS = {"bug": ("不具合の原因", 0), "suspect": ("不具合の可能性", 1), "info": ("参考", 2), "auto": ("差分", 3)}
TAGS = {"replace": "値の変化", "insert": "不正側に挿入", "delete": "不正側で欠落", "equal": "差分なし"}


def _hex_panel(title, d, focus, level, others, noise, ma):
    esc = html.escape
    s, e = focus
    last = min(max(e, s + 1), s + 96)
    first_row = max(s - 16, 0) & ~15
    end = min(last + 16, len(d))
    cls = {}
    for rs, kind in ((others, "d"), (noise, "n")):
        for r0, r1 in rs:
            for i in range(max(r0, first_row), min(r1, end)):
                cls[i] = kind
    for i in range(s, min(e, end)):
        cls[i] = "x"
    if s == e and s < len(d):
        cls[s] = "c"
    rows = []
    for i in range(first_row, end, 16):
        hexes, chars = [], []
        for j, byte in enumerate(d[i: i + 16]):
            k = cls.get(i + j, "")
            names = ("g " if j == 8 else "") + k
            tip = f' title="0x{i + j:x}{" " + esc(ma.labels(i + j, i + j + 1), quote=True) if ma else ""}"' if k else ""
            hexes.append(f'<u class="{names.strip()}"{tip}>{byte:02x}</u>')
            ch = esc(chr(byte)) if 32 <= byte < 127 else "·"
            chars.append(f'<u class="{k}">{ch}</u>')
        pad = '<u>&nbsp;</u>' * (16 - len(d[i: i + 16]))
        rows.append(f'<div><span class="o">{i:08x}</span>{"".join(hexes)}{pad}<span class="s">{"".join(chars)}</span></div>')
    body = "".join(rows) or '<div class="sub">この位置にデータはありません（ファイル終端の後）</div>'
    more = f'<div class="more">先頭 96 バイトのみ表示（全 {e - s} バイト）</div>' if e - s > 96 else ""
    return f'<div class="panel {level}"><h3>{esc(title)}</h3><div class="hex">{body}</div>{more}</div>'


def _parse_notes(path):
    if not path:
        return "", []
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    return doc.get("summary", ""), doc.get("notes", [])


def cmd_report(args):
    esc = html.escape
    a, b = read(args.a), read(args.b)
    defs = load_defs(args)
    ma = decode(defs, a, args.layout, args.endian) if defs else None
    mb = decode(defs, b, args.layout, args.endian) if defs else None
    fa_map, fb_map = (field_map(ma), field_map(mb)) if defs else ({}, {})
    regions = align(a, b) if a != b else []
    is_noise = load_mask(args.mask)
    noise = [r for r in regions if is_noise(r)]
    real = [r for r in regions if not is_noise(r)]
    summary, notes = _parse_notes(args.notes)

    cards = {}
    for note in notes:
        o = int(str(note["offset"]), 0)
        ln = max(int(note.get("len", 1)), 1)
        level = note.get("level", "suspect")
        if level not in LEVELS:
            sys.exit(f"level は {', '.join(LEVELS)} のいずれかです: {level}")
        hit = next((r for r in regions if r[3] < o + ln and o < max(r[4], r[3] + 1)), None)
        if hit:
            key = hit
            if hit[2] - hit[1] == hit[4] - hit[3]:
                fa = (hit[1] + o - hit[3], hit[1] + o - hit[3] + ln)
            else:
                fa = (hit[1], hit[2])
        else:
            delta = sum((r[4] - r[3]) - (r[2] - r[1]) for r in regions if r[4] <= o)
            key = ("equal", o - delta, o - delta + ln, o, o + ln)
            fa = key[1:3]
        card = cards.setdefault(key, {"notes": [], "fa": fa, "fb": (o, o + ln)})
        card["notes"].append(note)
        card["fa"] = (min(card["fa"][0], fa[0]), max(card["fa"][1], fa[1]))
        card["fb"] = (min(card["fb"][0], o), max(card["fb"][1], o + ln))
    annotated = sorted(cards.items(), key=lambda kv: (min(LEVELS[n.get("level", "suspect")][1] for n in kv[1]["notes"]), kv[0][3]))
    plain = [r for r in real if r not in cards]
    limit = max(args.max - len(annotated), 0)
    entries = annotated + [(r, {"notes": [], "fa": (r[1], r[2]), "fb": (r[3], r[4])}) for r in plain[:limit]]
    omitted = len(plain) - min(limit, len(plain))

    html_cards, ticks = [], []
    size = max(len(b), 1)
    others_a = [(r[1], r[2]) for r in real]
    others_b = [(r[3], r[4]) for r in real]
    noise_a = [(r[1], r[2]) for r in noise]
    noise_b = [(r[3], r[4]) for r in noise]
    for n, (key, card) in enumerate(entries, 1):
        tag, a0, a1, b0, b1 = key
        level = min((n_.get("level", "suspect") for n_ in card["notes"]), key=lambda v: LEVELS[v][1]) if card["notes"] else "auto"
        fa, fb = card["fa"], card["fb"]
        ticks.append(f'<a class="{level}" href="#c{n}" title="#{n} 0x{b0:x}" style="left:{b0 / size * 100:.3f}%;width:{(b1 - b0) / size * 100:.3f}%"></a>')
        lines = "".join(
            f'<p class="note {x.get("level", "suspect")}"><b>{esc(x.get("title", ""))}</b>'
            f'{"<br>" + esc(x["detail"]) if x.get("detail") else ""}</p>' for x in card["notes"]
        )
        label = list(dict.fromkeys(ma.paths(fa[0], max(fa[1], fa[0] + 1)) + mb.paths(fb[0], max(fb[1], fb[0] + 1)))) if ma else []
        rows = "".join(
            f'<tr><td class="m">{esc(p)}</td><td class="m">{esc(fa_map[p].show) if p in fa_map else "（なし）"}</td>'
            f'<td class="m">{esc(fb_map[p].show) if p in fb_map else "（なし）"}</td></tr>'
            for p in [p for p in label if p in fa_map or p in fb_map][:8]
        )
        pads = [p for p in label if p.startswith("<padding")]
        table = f'<table><tr><th>フィールド</th><th>正常</th><th>不正</th></tr>{rows}</table>' if rows else ""
        hs = hints(a[fa[0]: fa[1]], b[fb[0]: fb[1]], ("正常", "不正"))
        hs += [f"{p} （構造体の隙間）" for p in pads[:3]]
        hint_html = '<ul class="h">' + "".join(f"<li>{esc(h)}</li>" for h in hs) + "</ul>" if hs else ""
        panels = (_hex_panel(f"正常: {os.path.basename(args.a)}", a, fa, level, others_a, noise_a, ma)
                  + _hex_panel(f"不正: {os.path.basename(args.b)}", b, fb, level, others_b, noise_b, mb))
        html_cards.append(
            f'<section class="card {level}" id="c{n}"><div class="head"><span class="badge">{LEVELS[level][0]}</span>'
            f'<h2>#{n} {esc(TAGS[tag])}</h2><span class="pos">正常 0x{a0:x} ({a1 - a0} バイト) / 不正 0x{b0:x} ({b1 - b0} バイト)</span></div>'
            f'{lines}<div class="panels">{panels}</div>{table}{hint_html}</section>'
        )
    noise_ticks = "".join(f'<i style="left:{r[3] / size * 100:.3f}%;width:{(r[4] - r[3]) / size * 100:.3f}%"></i>' for r in noise)
    shifts, obs = observations(a, b, regions)
    obs = [f"正常 0x{o:x} で {d:+d} バイト。以降の累計ずれ {c:+d}。これより後の差分は連鎖の可能性があります" for o, d, c in shifts[:5]] + obs
    if ma:
        obs = list(dict.fromkeys(defs.layout_warnings)) + obs
        obs += [f"正常: {i}" for i in ma.issues] + [f"不正: {i}" for i in mb.issues]
    if a == b:
        obs.append("2 つのファイルは完全に一致しています")
    obs_html = '<ul class="obs">' + "".join(f"<li>{esc(o)}</li>" for o in obs) + "</ul>" if obs else ""
    summary_html = f'<div class="summary">{esc(summary)}</div>' if summary else ""
    more = f'<p class="more">ほかに {omitted} 件の差分は省略しています（--max で増やせます）。</p>' if omitted else ""
    stats = [("正常のサイズ", f"{len(a):,}"), ("不正のサイズ", f"{len(b):,}"), ("差分", f"{len(real)} 件"),
             ("ノイズとして除外", f"{len(noise)} 件"),
             ("最初の差分", f"0x{real[0][3]:x}" if real else "なし")]
    stat_html = "".join(f"<div><b>{v}</b>{k}</div>" for k, v in stats)
    page = (
        f'<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{esc(args.title)}</title><style>{REPORT_CSS}</style></head><body><main>'
        f'<h1>{esc(args.title)}</h1><div class="sub">{esc(os.path.basename(args.a))} と {esc(os.path.basename(args.b))} の比較</div>'
        f'{summary_html}<div class="stats">{stat_html}</div>{obs_html}'
        f'<div class="sub">不正ファイル内の位置（クリックで該当箇所へ移動）</div><div class="map">{noise_ticks}{"".join(ticks)}</div>'
        f'<div class="scale"><span>0x0</span><span>0x{len(b):x}</span></div>'
        '<div class="legend"><span><i class="swatch bug" style="background:var(--bug-bg);outline:1.5px solid var(--bug)"></i>不具合の原因</span>'
        '<span><i class="swatch" style="background:var(--suspect-bg);outline:1.5px solid var(--suspect)"></i>不具合の可能性</span>'
        '<span><i class="swatch" style="background:var(--info-bg);outline:1.5px solid var(--info)"></i>参考</span>'
        '<span><i class="swatch" style="background:var(--auto-bg)"></i>その他の差分</span>'
        '<span><i class="swatch" style="background:var(--noise-bg)"></i>ノイズ（正常でも変わる）</span></div>'
        f'{"".join(html_cards)}{more}</main></body></html>'
    )
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"レポートを出力: {args.out} (カード {len(entries)} 枚、省略 {omitted} 件)")


def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def model_args(p):
        p.add_argument("--defs", nargs="+", help="C/C++ header(s) with the struct definitions")
        p.add_argument("--layout", help="e.g. Header,Record[Header.count],Footer or Header,Record* or Body@Header.offset")
        p.add_argument("--ptr", type=int, default=8, help="pointer size (default 8)")
        p.add_argument("--long", type=int, default=4, help="sizeof(long) (default 4, Windows)")
        p.add_argument("--pack", type=int, help="default #pragma pack / compiler packing")
        p.add_argument("--endian", choices=["little", "big"], default="little")
        p.add_argument("--define", action="append", metavar="NAME=VALUE",
                       help="integer constant for array sizes; overrides the headers (repeatable)")

    p = sub.add_parser("overview", help="size, entropy, fills, record period, strings")
    p.add_argument("file")
    p.add_argument("--max", type=int, default=20)
    p.set_defaults(fn=cmd_overview)

    p = sub.add_parser("view", help="hex window of one or more files")
    p.add_argument("files", nargs="+")
    p.add_argument("--at", default="0")
    p.add_argument("--len", default="256")
    p.set_defaults(fn=cmd_view)

    p = sub.add_parser("decode", help="decode file using C struct definitions")
    p.add_argument("file")
    model_args(p)
    p.add_argument("--grep", help="regex filter on field path")
    p.add_argument("--max", type=int, default=200)
    p.set_defaults(fn=cmd_decode)

    p = sub.add_parser("diff", help="alignment-aware diff of two files")
    p.add_argument("a")
    p.add_argument("b")
    model_args(p)
    p.add_argument("--mask", help="noise mask from multi --save-mask")
    p.add_argument("--max", type=int, default=40)
    p.set_defaults(fn=cmd_diff)

    p = sub.add_parser("report", help="standalone HTML: side-by-side bytes with highlights and comments")
    p.add_argument("a", help="good file")
    p.add_argument("b", help="bad file")
    model_args(p)
    p.add_argument("--mask", help="noise mask from multi --save-mask")
    p.add_argument("--notes", help="JSON with summary and per-byte comments")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--title", default="バイナリ比較レポート")
    p.add_argument("--max", type=int, default=40, help="max number of cards")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("multi", help="separate noise from anomalies using several good files")
    p.add_argument("--good", nargs="+", required=True)
    p.add_argument("--bad", nargs="+", required=True)
    model_args(p)
    p.add_argument("--save-mask")
    p.add_argument("--max", type=int, default=40)
    p.set_defaults(fn=cmd_multi)

    p = sub.add_parser("check", help="integrity: layout, implausible values, checksum and length hypotheses")
    p.add_argument("files", nargs="+")
    model_args(p)
    p.add_argument("--expect", action="append", help="e.g. 'Header.size==FILESIZE'")
    p.add_argument("--max", type=int, default=20)
    p.set_defaults(fn=cmd_check)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
