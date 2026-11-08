"""Seeded-defect tests for binx.py. Run: python tests/test_binx.py"""
import json
import os
import random
import re
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import binx  # noqa: E402

HEADER = """
#define NAME_LEN 8
enum State { IDLE, RUNNING = 5, ERROR_STATE };
#pragma pack(push, 1)
typedef struct { uint32_t magic; uint16_t count; uint64_t stamp; } Packed;
#pragma pack(pop)
typedef struct {
    uint32_t magic;
    uint16_t count;      // 2 bytes of padding follow
    uint64_t stamp;
    uint32_t crc;
} Header;
struct Record {
    int id;
    char name[NAME_LEN];
    float score;
    enum State state;
    unsigned flag_a : 1;
    unsigned flag_b : 3;
    unsigned other : 28;
    void* owner;
};
class WithMethods {
public:
    int get() const { return value; }
    int value;
    std::string label;
};
"""


def random_bytes(n, seed):
    return random.Random(seed).randbytes(n)


def rec(i, name=b"item", score=1.5, state=5, owner=0):
    return struct.pack("<i8sfiIQ", i, name.ljust(8, b"\0"), score, state, 0x13, owner)


def file_of(records, stamp=1000, count=None, crc=True, pad=b"\0\0"):
    body = b"".join(records)
    head = struct.pack("<IH", 0x4B415442, len(records) if count is None else count) + pad + struct.pack("<Q", stamp)
    value = zlib.crc32(body) if crc is True else crc
    return head + struct.pack("<I", value) + b"\0\0\0\0" + body


LAYOUT = "Header,Record[Header.count]"

VAR_SCHEMA = b"""
struct Head { uint32_t magic; uint16_t version; uint16_t count; };
struct Tag { uint8_t kind; uint8_t len; uint8_t value[len]; };
struct Item {
    uint16_t name_len;
    char name[name_len];
    uint32_t score;
    if (Head.version >= 2) { uint32_t extra; }
    uint8_t tag_count;
    Tag tags[tag_count];
    uint8_t pad[(4 - name_len % 4) % 4];
};
"""
VAR_LAYOUT = "Head,Item[Head.count]"


def var_item(name, score=1, tags=(), version=2, extra=7, name_len=None):
    out = struct.pack("<H", len(name) if name_len is None else name_len) + name + struct.pack("<I", score)
    if version >= 2:
        out += struct.pack("<I", extra)
    out += bytes([len(tags)])
    for kind, value in tags:
        out += bytes([kind, len(value)]) + value
    return out + b"\xee" * ((4 - len(name) % 4) % 4)


def var_file(items, version=2):
    return struct.pack("<IHH", 0x4B415442, version, len(items)) + b"".join(items)


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.h = cls.path("a.h", HEADER.encode())
        cls.recs = [rec(i) for i in range(4)]

    @classmethod
    def path(cls, name, data):
        p = os.path.join(cls.dir, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def run_cli(self, *argv):
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "binx.py"), *argv],
                           capture_output=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        return r.stdout.decode("utf-8")

    def defs(self):
        d = binx.Defs()
        d.feed(HEADER)
        return d

    def test_struct_layout(self):
        d = self.defs()
        self.assertEqual(d.types["Packed"].size, 14)
        self.assertEqual(d.types["Header"].size, 24)
        rec_t = d.types["Record"]
        self.assertEqual(rec_t.size, 32)
        self.assertEqual({f.name: f.offset for f in rec_t.fields}["owner"], 24)

    def test_unknown_member_warns(self):
        d = self.defs()
        self.assertTrue(d.types["WithMethods"].incomplete)
        self.assertTrue(any("string" in w for w in d.warnings))

    @staticmethod
    def parse(src):
        d = binx.Defs()
        d.feed(src)
        return d

    def test_msvc_sized_integers(self):
        t = self.parse("struct A { int x; unsigned __int64 v; __int32 w; };").types["A"]
        self.assertEqual({f.name: f.offset for f in t.fields}, {"x": 0, "v": 8, "w": 16})
        self.assertEqual(t.size, 24)
        self.assertFalse(t.incomplete)

    def test_unparsable_member_warns_instead_of_disappearing(self):
        d = self.parse("struct A { int x; unsigned MYINT y; int z; };")
        self.assertTrue(d.types["A"].incomplete)
        self.assertTrue(any(w.startswith("A:") for w in d.warnings))

    def test_cpp_attributes_do_not_drop_member(self):
        t = self.parse("struct A { [[maybe_unused]] int x; int y; };").types["A"]
        self.assertEqual(t.size, 8)
        self.assertFalse(t.incomplete)

    def test_undefined_array_length_warns_without_crash(self):
        d = self.parse("struct A { int x; char path[MAX_PATH]; int y; };\nstruct B { int b; };")
        self.assertTrue(d.types["A"].incomplete)
        self.assertTrue(any("MAX_PATH" in w for w in d.warnings))
        self.assertEqual(d.types["B"].size, 4)  # parsing continues after the failure

    def test_define_option_supplies_constant_and_wins_over_header(self):
        h = self.path("define.h", b"#define LEN 8\nstruct A { int x; char path[MAX_PATH]; int y; char t[LEN]; };")
        out = self.run_cli("decode", self.path("define.bin", b"\1" * 276), "--defs", h, "--layout", "A",
                           "--define", "MAX_PATH=260", "--define", "LEN=4")
        self.assertIn("sizeof(A) = 272", out)
        self.assertNotIn("[警告]", out)

    def test_sizeof_in_array_length(self):
        src = "struct S { int a; int b; };\nstruct A { char a[sizeof(int)*2]; char b[sizeof(unsigned short)]; char c[sizeof(void*)]; char d[sizeof(struct S)]; };"
        t = self.parse(src).types["A"]
        self.assertEqual([f.type.n for f in t.fields], [8, 2, 8, 8])

    def test_forward_declared_typedef(self):
        d = self.parse("typedef struct _Foo Foo;\nstruct _Foo { int a; int b; };\nstruct Bar { Foo f; int c; };")
        self.assertEqual(d.types["Foo"].size, 8)
        self.assertFalse(d.types["Foo"].incomplete)
        self.assertEqual(d.types["Bar"].size, 12)
        self.assertEqual(d.warnings, [])

    def test_methods_do_not_warn(self):
        src = """struct Foo; struct A {
            explicit A(int v);
            inline A();
            ~A();
            std::string name() const;
            std::vector<int> items() const { return {}; }
            Foo* make();
            A& operator=(const A& o);
            bool operator==(const A& o) const;
            [[nodiscard]] int get() const;
            int x;
        };"""
        d = self.parse(src)
        self.assertEqual(d.warnings, [])
        self.assertFalse(d.types["A"].incomplete)
        self.assertEqual(d.types["A"].size, 4)

    def test_function_like_macro_member_still_warns(self):
        d = self.parse("struct A { int x; DECLARE_BUFFER(buf); };")
        self.assertTrue(d.types["A"].incomplete)

    def test_inheritance_and_nested_incomplete_are_flagged_for_layout(self):
        src = b"struct Base { int b; };\nstruct D : Base { int x; };\nstruct Outer { struct D d; };"
        h = self.path("inherit.h", src)
        data = self.path("inherit.bin", b"\1" * 8)
        out = self.run_cli("decode", data, "--defs", h, "--layout", "Outer")
        self.assertIn("レイアウト対象 Outer", out)
        report = os.path.join(self.dir, "inherit.html")
        self.run_cli("report", data, data, "--defs", h, "--layout", "Outer", "-o", report)
        with open(report, encoding="utf-8") as f:
            self.assertIn("レイアウト対象 Outer", f.read())

    def test_flag_enum_combination_is_valid(self):
        h = self.path("flags.h", b"enum F { NONE = 0, A = 1, B = 2, C = 4 }; struct R { enum F f; };")
        ok = self.run_cli("check", self.path("flags.bin", struct.pack("<I", 3)), "--defs", h, "--layout", "R")
        self.assertNotIn("未定義の enum", ok)
        self.assertIn("3 (A|B)", self.run_cli("decode", self.path("flags.bin", struct.pack("<I", 3)), "--defs", h, "--layout", "R"))
        bad = self.run_cli("check", self.path("flags2.bin", struct.pack("<I", 8)), "--defs", h, "--layout", "R")
        self.assertIn("未定義の enum", bad)

    def test_sequential_enum_is_not_treated_as_flags(self):
        h = self.path("seq.h", b"enum S { A, B, C, D, E }; struct R { enum S s; };")
        out = self.run_cli("check", self.path("seq.bin", struct.pack("<I", 5)), "--defs", h, "--layout", "R")
        self.assertIn("未定義の enum", out)

    def test_unseen_value_in_varying_field_is_weak_and_unmasked(self):
        h = self.path("str.h", b"struct R { char n[8]; };")
        g1, g2 = self.path("str1", b"aaaaaaa\0"), self.path("str2", b"ccccccc\0")
        bad = self.path("str3", b"bbbbbbb\0")
        mask = os.path.join(self.dir, "str-mask.json")
        out = self.run_cli("multi", "--good", g1, g2, "--bad", bad, "--defs", h, "--layout", "R", "--save-mask", mask)
        self.assertIn("R.n", out.split("【弱】")[1])
        with open(mask, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["noise"], [])
        self.assertIn("差分領域: 1 件", self.run_cli("diff", g1, bad, "--mask", mask))

    def test_seen_value_in_varying_field_stays_noise(self):
        h = self.path("seen.h", b"struct R { char n[8]; };")
        g1, g2 = self.path("seen1", b"aaaaaaa\0"), self.path("seen2", b"ccccccc\0")
        mask = os.path.join(self.dir, "seen-mask.json")
        self.run_cli("multi", "--good", g1, g2, "--bad", self.path("seen3", b"ccccccc\0"),
                     "--defs", h, "--layout", "R", "--save-mask", mask)
        with open(mask, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["noise"], [[0, 7]])

    def test_bad_layout_expression_is_a_clean_error(self):
        h = self.path("expr.h", b"struct R { int a; };")
        r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "binx.py"), "decode", self.path("expr.bin", b"\0" * 8),
                            "--defs", h, "--layout", "R,R[R.nope]"],
                           capture_output=True, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        self.assertNotEqual(r.returncode, 0)
        err = r.stderr.decode("utf-8")
        self.assertNotIn("Traceback", err)
        self.assertIn("R.nope", err)

    def var_defs(self):
        return self.parse(VAR_SCHEMA.decode())

    def test_variable_length_fields_decode(self):
        data = var_file([var_item(b"abc", 10, [(1, b"xy"), (2, b"")]), var_item(b"longer-name", 20, [(9, b"z")])])
        m = binx.decode(self.var_defs(), data, VAR_LAYOUT, "little")
        f = binx.field_map(m)
        self.assertEqual(m.issues, [])
        self.assertEqual(f["Item[0].name"].value, "abc")
        self.assertEqual(f["Item[0].tags[0].value"].raw, b"xy")
        self.assertEqual(f["Item[1].name"].value, "longer-name")
        self.assertEqual(f["Item[1].score"].value, 20)
        self.assertEqual(f["Item[1].tags[0].value"].raw, b"z")
        second = 8 + len(var_item(b"abc", 10, [(1, b"xy"), (2, b"")]))
        self.assertEqual(f["Item[1].name_len"].offset, second)

    def test_conditional_field_follows_version(self):
        m = binx.decode(self.var_defs(), var_file([var_item(b"abcd", version=1)], version=1), VAR_LAYOUT, "little")
        self.assertEqual(m.issues, [])
        self.assertNotIn("Item[0].extra", binx.field_map(m))
        m = binx.decode(self.var_defs(), var_file([var_item(b"abcd")]), VAR_LAYOUT, "little")
        self.assertEqual(binx.field_map(m)["Item[0].extra"].value, 7)

    def test_else_branch(self):
        d = self.parse("struct T { uint8_t k; if (k == 1) { uint16_t a; } else if (!k) { uint8_t b; } else { uint32_t c; } };")
        for raw, name in ((b"\1\1\0", "a"), (b"\0\1", "b"), (b"\2\1\0\0\0", "c")):
            m = binx.decode(d, raw, "T", "little")
            self.assertEqual(m.issues, [])
            self.assertIn(f"T.{name}", binx.field_map(m))

    def test_corrupt_length_is_reported_with_field_and_value(self):
        data = var_file([var_item(b"abcd", 10), var_item(b"efgh", 20, name_len=0xFFFF)])
        out = self.run_cli("decode", self.path("corrupt.bin", data), "--defs", self.path("var.h", VAR_SCHEMA), "--layout", VAR_LAYOUT)
        self.assertIn("Item[0].score", out)
        issue = next(line for line in out.splitlines() if line.startswith("[構造]"))
        self.assertIn("Item[1].name", issue)
        self.assertIn("65535", issue)

    def test_truncated_inside_variable_array_is_reported(self):
        data = var_file([var_item(b"abcd", 10, [(1, b"xxxx"), (2, b"yyyy")])])[:-6]
        m = binx.decode(self.var_defs(), data, VAR_LAYOUT, "little")
        self.assertTrue(any("Item[0].tags[1]" in s for s in m.issues), m.issues)

    def test_diff_compares_fields_by_path_across_a_shift(self):
        a = var_file([var_item(b"abcd", 10), var_item(b"efgh", 20)])
        b = var_file([var_item(b"abcd-long", 10), var_item(b"efgh", 20)])
        h = self.path("var.h", VAR_SCHEMA)
        out = self.run_cli("diff", self.path("va", a), self.path("vb", b), "--defs", h, "--layout", VAR_LAYOUT)
        fields = out.split("フィールド単位の差分:")[1]
        self.assertIn("Item[0].name", fields)
        self.assertNotIn("Item[0].score", fields)
        self.assertNotIn("Item[1]", fields)
        self.assertNotIn("ずれの結果", fields)

    def test_multi_with_different_sizes_uses_fields_and_empty_mask(self):
        good = [var_file([var_item(n, 10, extra=e)]) for n, e in ((b"aaaa", 1), (b"longer-name", 2))]
        bad = var_file([var_item(b"bb", 99, extra=1)])
        gp = [self.path(f"vg{i}", d) for i, d in enumerate(good)]
        mask = os.path.join(self.dir, "var-mask.json")
        out = self.run_cli("multi", "--good", *gp, "--bad", self.path("vbad", bad), "--defs", self.path("var.h", VAR_SCHEMA),
                           "--layout", VAR_LAYOUT, "--save-mask", mask)
        strong = out.split("【強】正常では一定")[1].split("【弱】")[0]
        self.assertIn("Item[0].score", strong)
        self.assertNotIn("バイト比較の結果", out.split("正常同士で変動するバイト")[0])
        self.assertNotIn("【強】正常では常に同じなのに不正で異なるバイト", out)
        with open(mask, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["noise"], [])

    def test_length_prefixed_string_needs_no_terminator(self):
        data = var_file([var_item(b"abcd")])
        out = self.run_cli("check", self.path("lstr.bin", data), "--defs", self.path("var.h", VAR_SCHEMA), "--layout", VAR_LAYOUT)
        self.assertNotIn("NUL 終端がない", out)

    def test_terminated_rest_and_until_arrays(self):
        src = """struct E { uint8_t kind; uint8_t v; };
        struct Z { char s[__zstr]; wchar_t w[__zstr]; E list[__until(kind == 0)]; uint16_t rest[__rest]; };"""
        data = b"hi\0" + "ok".encode("utf-16-le") + b"\0\0" + b"\1\5\2\6\0\7" + struct.pack("<HH", 8, 9)
        m = binx.decode(self.parse(src), data, "Z", "little")
        f = binx.field_map(m)
        self.assertEqual(m.issues, [])
        self.assertEqual(f["Z.s"].value, "hi")
        self.assertEqual(f["Z.w"].value, "ok")
        self.assertEqual(f["Z.list[2].v"].value, 7)
        self.assertEqual(f["Z.rest[1]"].value, 9)

    def test_missing_terminator_is_reported(self):
        m = binx.decode(self.parse("struct Z { char s[__zstr]; };"), b"no-end", "Z", "little")
        self.assertTrue(any("Z.s" in s for s in m.issues), m.issues)

    def test_nested_scope_and_static_struct_keeps_its_layout(self):
        src = """struct S { uint8_t a; uint32_t b; };
        struct In { uint8_t m; uint8_t both[n + m]; };
        struct D { uint8_t n; S s; In in; };"""
        data = b"\1" + b"\2\0\0\0" + struct.pack("<I", 5) + b"\2" + b"abc"
        m = binx.decode(self.parse(src), data, "D", "little")
        f = binx.field_map(m)
        self.assertEqual(m.issues, [])
        self.assertEqual(f["D.s.b"].offset, 5)
        self.assertEqual(f["D.in.both"].raw, b"abc")

    def test_corrupted_files_never_crash_the_decoder(self):
        rng = random.Random(3)
        d = self.var_defs()
        base = var_file([var_item(b"abcd", 10, [(1, b"xy"), (2, b"pqrs")]), var_item(b"efghij", 20, [(9, b"z")])])
        for _ in range(1500):
            data = bytearray(base)
            for _ in range(rng.randint(1, 6)):
                data[rng.randrange(len(data))] = rng.choice([0, 1, 0x7F, 0xFF, rng.randrange(256)])
            data = bytes(data[:rng.randint(0, len(data))]) if rng.random() < 0.3 else bytes(data)
            m = binx.decode(d, data, VAR_LAYOUT, "little")
            binx.plausibility(m, data)

    def test_non_finite_length_is_reported(self):
        d = self.parse("struct T { float v; uint8_t b[v]; };")
        for raw in (b"\x00\x00\x80\x7f", b"\x00\x00\xc0\x7f"):  # inf, NaN
            m = binx.decode(d, raw + b"abcd", "T", "little")
            self.assertTrue(any("T.b" in s for s in m.issues), m.issues)

    def decode_output(self, header, layout, data):
        """Decode in a subprocess so that a hang fails the test instead of blocking the run."""
        h, d = self.path("limit.h", header.encode()), self.path("limit.bin", data)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "binx.py"), "decode", d, "--defs", h, "--layout", layout],
                           capture_output=True, timeout=20, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        return r.stdout.decode("utf-8")

    def test_negative_offset_on_repeated_item_stops_with_an_issue(self):
        out = self.decode_output("struct H { int32_t off; }; struct R { uint32_t v; };", "H,R*@H.off",
                                 struct.pack("<i", -2000000000) + b"\0" * 32)
        self.assertIn("範囲外", out)

    def test_negative_offset_does_not_read_from_the_end_of_the_file(self):
        out = self.decode_output("struct H { int32_t off; }; struct R { uint32_t a; uint32_t b; };", "H,R@H.off",
                                 struct.pack("<i", -2) + b"\1" * 4)
        self.assertIn("範囲外", out)
        self.assertNotIn("R.a", out)

    def test_offset_past_end_is_reported(self):
        out = self.decode_output("struct H { uint32_t off; }; struct R { uint32_t v; };", "H,R@H.off", struct.pack("<I", 1000))
        self.assertIn("範囲外", out)

    def test_non_finite_offset_is_reported(self):
        out = self.decode_output("struct H { float off; }; struct R { uint32_t v; };", "H,R@H.off", b"\x00\x00\x80\x7f" + b"\0" * 8)
        self.assertIn("[構造]", out)

    def test_negative_count_is_reported(self):
        out = self.decode_output("struct H { int32_t c; }; struct R { uint32_t v; };", "H,R[H.c]", struct.pack("<i", -1) + b"\0" * 8)
        self.assertIn("負", out)

    def test_huge_shift_in_length_is_reported(self):
        for shift in (20000, 0xFFFFFFFF):
            out = self.decode_output("struct T { uint32_t s; uint8_t b[1 << s]; };", "T", struct.pack("<I", shift) + b"abcd")
            self.assertIn("T.b", next(line for line in out.splitlines() if line.startswith("[構造]")))

    def test_normal_shift_in_length_still_works(self):
        out = self.decode_output("struct T { uint8_t s; uint8_t b[1 << s]; };", "T", b"\2abcd")
        self.assertNotIn("[構造]", out)
        self.assertIn("T.b", out)

    def test_zero_size_elements_are_reported(self):
        out = self.decode_output("struct E { }; struct T { uint32_t n; E e[n]; };", "T", struct.pack("<I", 0xFFFFFFF0))
        self.assertIn("T.e", next(line for line in out.splitlines() if line.startswith("[構造]")))
        out = self.decode_output("struct E { }; struct T { E e[__zstr]; };", "T", b"abcd")
        self.assertIn("T.e", next(line for line in out.splitlines() if line.startswith("[構造]")))

    def test_variable_member_in_union_warns(self):
        d = self.parse("struct U { uint8_t n; union { char a[n]; int b; } u; };")
        self.assertTrue(d.types["U"].incomplete)

    def test_report_labels_fields_that_exist_only_in_bad_file(self):
        a = var_file([var_item(b"abcd", 10)])
        b = var_file([var_item(b"abcd", 10), var_item(b"new!", 20)])
        offset = len(a)
        notes = self.path("vnotes.json", json.dumps({"notes": [
            {"offset": hex(offset), "len": 2, "level": "suspect", "title": "extra item"}]}).encode())
        out_html = os.path.join(self.dir, "v.html")
        self.run_cli("report", self.path("ra", a), self.path("rb2", b), "--defs", self.path("var.h", VAR_SCHEMA),
                     "--layout", VAR_LAYOUT, "--notes", notes, "-o", out_html)
        with open(out_html, encoding="utf-8") as f:
            self.assertIn("Item[1].name_len", f.read())

    def test_decode_fields(self):
        m = binx.decode(self.defs(), file_of(self.recs), LAYOUT, "little")
        f = binx.field_map(m)
        self.assertEqual(f["Record[2].id"].value, 2)
        self.assertEqual(f["Record[0].name"].value, "item")
        self.assertEqual(f["Record[0].flag_a"].value, 1)
        self.assertEqual(f["Record[0].flag_b"].value, 1)
        self.assertIn("RUNNING", f["Record[0].state"].show)
        self.assertEqual(m.issues, [])

    def test_count_too_large_is_reported(self):
        m = binx.decode(self.defs(), file_of(self.recs, count=5), LAYOUT, "little")
        self.assertTrue(any("途切れ" in s for s in m.issues))

    def test_align_finds_insertion_point(self):
        a = bytes(range(256)) * 2
        b = a[:100] + b"\xaa\xbb\xcc\xdd" + a[100:]
        ops = binx.align(a, b)
        self.assertEqual(len(ops), 1)
        self.assertEqual(ops[0][0], "insert")
        self.assertEqual(ops[0][1], 100)
        self.assertEqual(ops[0][4] - ops[0][3], 4)

    def test_same_size_change_is_positional(self):
        a = random_bytes(4096, seed=1)
        self.assertNotEqual(a[1000], 0xCC)
        b = bytearray(a)
        b[1000:1004] = b"\xcc\xcc\xcc\xcc"
        ops = binx.align(a, bytes(b))
        self.assertEqual([(o[1], o[2]) for o in ops], [(1000, 1004)])

    def test_crlf_detected(self):
        a = b"".join(random_bytes(40, seed=i).replace(b"\n", b"x").replace(b"\r", b"y") + b"\n" for i in range(8))
        b = a.replace(b"\n", b"\r\n")
        out = self.run_cli("diff", self.path("lf", a), self.path("crlf", b))
        self.assertIn("テキストモード", out)

    def test_truncation_at_boundary(self):
        a = random_bytes(8192 + 100, seed=2)
        out = self.run_cli("diff", self.path("full", a), self.path("cut", a[:8192]))
        self.assertIn("途切れている", out)
        self.assertIn("4096", out)

    def test_multi_masks_noise_and_names_field(self):
        good = [file_of(self.recs, stamp=s) for s in (1000, 2345, 987654)]
        bad_recs = list(self.recs)
        bad_recs[2] = rec(2, state=99)
        bad = file_of(bad_recs, stamp=3000, crc=zlib.crc32(b"".join(self.recs)))
        gp = [self.path(f"g{i}", d) for i, d in enumerate(good)]
        bp = self.path("bad", bad)
        mask = os.path.join(self.dir, "mask.json")
        out = self.run_cli("multi", "--good", *gp, "--bad", bp, "--defs", self.h, "--layout", LAYOUT, "--save-mask", mask)
        strong = out.split("【強】正常では一定")[1].split("【弱】")[0]
        self.assertIn("Record[2].state", strong)
        self.assertNotIn("Header.stamp", strong)
        with open(mask, encoding="utf-8") as f:
            self.assertTrue(json.load(f)["noise"])
        masked = self.run_cli("diff", gp[0], bp, "--mask", mask)
        self.assertIn("ノイズとして", masked)

    def test_mask_keeps_out_of_range_change_in_diff_and_report(self):
        # Separate the benign change from the anomaly so merge() cannot
        # accidentally keep the anomaly visible on behalf of another region.
        g1 = self.path("range-g1", bytes([10]) + b"\0" * 15 + bytes([10]))
        g2 = self.path("range-g2", bytes([20]) + b"\0" * 15 + bytes([20]))
        bad = self.path("range-bad", bytes([15]) + b"\0" * 15 + bytes([255]))
        mask = os.path.join(self.dir, "range-mask.json")
        self.run_cli("multi", "--good", g1, g2, "--bad", bad, "--save-mask", mask)
        is_noise = binx.load_mask(mask)
        self.assertTrue(is_noise(("replace", 0, 1, 0, 1)))
        self.assertFalse(is_noise(("replace", 16, 17, 16, 17)))
        out = self.run_cli("diff", g1, bad, "--mask", mask)
        self.assertIn("最初の差分: A@0x10", out)
        report = os.path.join(self.dir, "range-report.html")
        self.run_cli("report", g1, bad, "--mask", mask, "-o", report)
        with open(report, encoding="utf-8") as f:
            page = f.read()
        self.assertIn("0x10", page)
        self.assertRegex(page, r'<u class="(?:g )?x"[^>]*>ff</u>')

    def test_mask_does_not_hide_structural_changes(self):
        mask = self.path("structural-mask.json", b'{"noise": [[0, 32]]}')
        is_noise = binx.load_mask(mask)
        self.assertTrue(is_noise(("replace", 4, 8, 4, 8)))
        self.assertFalse(is_noise(("delete", 4, 8, 4, 4)))
        self.assertFalse(is_noise(("insert", 4, 4, 4, 8)))
        self.assertFalse(is_noise(("replace", 4, 8, 8, 12)))

    def test_check_finds_crc_broken_in_bad(self):
        good = file_of(self.recs)
        bad_recs = list(self.recs)
        bad_recs[1] = rec(1, score=9.25)
        bad = file_of(bad_recs, crc=zlib.crc32(b"".join(self.recs)))
        g, b = self.path("gc", good), self.path("bc", bad)
        found = binx.checksum_search(good)
        hyp = ("crc32", 16, 24, "little")  # stored at 0x10, covers the body after the header padding
        self.assertIn(hyp, found)
        self.assertTrue(binx.checksum_holds(good, hyp))
        self.assertFalse(binx.checksum_holds(bad, hyp))
        out = self.run_cli("check", g, b)
        self.assertIn("gc=OK  bc=NG", out)

    def test_check_flags_bad_values(self):
        recs = [rec(0, name=b"ab\0junk", score=float("nan"), state=42, owner=0x7FF612345678)]
        d = file_of(recs, pad=b"\xcc\xcc")
        out = self.run_cli("check", self.path("v", d), "--defs", self.h, "--layout", LAYOUT,
                           "--expect", "Header.count*sizeof(Record)+sizeof(Header)==FILESIZE",
                           "--expect", "Header.count==2")
        for word in ("NaN", "未定義の enum", "ポインタ", "NUL より後", "padding", "OK: Header.count*", "NG: Header.count==2"):
            self.assertIn(word, out)

    def test_report_highlights_annotated_byte(self):
        good = file_of(self.recs)
        bad_recs = list(self.recs)
        bad_recs[2] = rec(2, state=99)
        bad = file_of(bad_recs, crc=zlib.crc32(b"".join(self.recs)))
        offset = 24 + 32 * 2 + 16
        notes = self.path("notes.json", json.dumps({
            "summary": "state が <壊れて> います",
            "notes": [{"offset": hex(offset), "len": 1, "level": "suspect",
                       "title": "ここの1バイトが不具合の可能性", "detail": "enum の範囲外です"}],
        }, ensure_ascii=False).encode("utf-8"))
        out_html = os.path.join(self.dir, "r.html")
        self.run_cli("report", self.path("rg", good), self.path("rb", bad), "--defs", self.h, "--layout", LAYOUT,
                     "--notes", notes, "-o", out_html)
        with open(out_html, encoding="utf-8") as f:
            page = f.read()
        self.assertIn("ここの1バイトが不具合の可能性", page)
        self.assertIn("&lt;壊れて&gt;", page)
        self.assertIn("Record[2].state", page)
        cells = re.findall(r'<u class="(?:g )?x"', page)
        self.assertEqual(len(cells), 4)  # one highlighted byte, hex + ascii, both panels
        self.assertIn(">63</u>", page)

    def test_overview_finds_record_period(self):
        d = file_of([rec(i, name=b"item%d" % (i % 7)) for i in range(300)])
        out = self.run_cli("overview", self.path("ov", d))
        self.assertIn("32 バイト", out)


if __name__ == "__main__":
    unittest.main(verbosity=1)
