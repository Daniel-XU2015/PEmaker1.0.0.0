import struct
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText


def align(v, a):
    return (v + a - 1) // a * a


TEMPLATES = {
    "messagebox": {
        "name": "MessageBox 弹框 (GUI)",
        "imports": [("user32.dll", ["MessageBoxA"]),
                    ("kernel32.dll", ["ExitProcess"])],
        "subsystem": 2,
        "params": ["caption", "text"],
    },
    "console_print": {
        "name": "Console 打印文本 (CONSOLE)",
        "imports": [("kernel32.dll", ["GetStdHandle", "WriteFile", "ExitProcess"])],
        "subsystem": 3,
        "params": ["console_msg"],
    },
    "exit_only": {
        "name": "仅调用 ExitProcess 退出",
        "imports": [("kernel32.dll", ["ExitProcess"])],
        "subsystem": 3,
        "params": [],
    },
    "raw_shellcode": {
        "name": "执行自定义 Shellcode (hex) + 额外导入",
        "imports": [("kernel32.dll", ["ExitProcess"])],
        "subsystem": 2,
        "params": ["shellcode_hex", "extra_imports"],
    },
}


def _code_x86(template, iat_va, strings, params):
    c = bytearray()
    if template == "messagebox":
        c += b"\x6A\x00"
        c += b"\x68" + struct.pack("<I", strings["caption"][1])
        c += b"\x68" + struct.pack("<I", strings["text"][1])
        c += b"\x6A\x00"
        c += b"\xFF\x15" + struct.pack("<I", iat_va["MessageBoxA"])
        c += b"\x6A\x00"
        c += b"\xFF\x15" + struct.pack("<I", iat_va["ExitProcess"])
        c += b"\xC3"
    elif template == "console_print":
        msg_len = len(params["console_msg"].encode("ascii", "ignore"))
        c += b"\x6A\xF5"
        c += b"\xFF\x15" + struct.pack("<I", iat_va["GetStdHandle"])
        c += b"\x6A\x00"
        c += b"\x6A\x00"
        c += b"\x68" + struct.pack("<I", msg_len)
        c += b"\x68" + struct.pack("<I", strings["msg"][1])
        c += b"\x50"
        c += b"\xFF\x15" + struct.pack("<I", iat_va["WriteFile"])
        c += b"\x6A\x00"
        c += b"\xFF\x15" + struct.pack("<I", iat_va["ExitProcess"])
        c += b"\xC3"
    elif template == "exit_only":
        c += b"\x6A\x00"
        c += b"\xFF\x15" + struct.pack("<I", iat_va["ExitProcess"])
        c += b"\xC3"
    return bytes(c)


def _code_x64(template, iat_va, strings, params):
    c = bytearray()
    if template == "messagebox":
        c += b"\x48\x83\xEC\x28"
        c += b"\x48\x31\xC9"
        c += b"\x48\xBA" + struct.pack("<Q", strings["text"][1])
        c += b"\x49\xB8" + struct.pack("<Q", strings["caption"][1])
        c += b"\x4D\x31\xC9"
        c += b"\x48\xA1" + struct.pack("<Q", iat_va["MessageBoxA"])
        c += b"\xFF\xD0"
        c += b"\x48\x83\xC4\x28"
        c += b"\x48\x31\xC9"
        c += b"\x48\xA1" + struct.pack("<Q", iat_va["ExitProcess"])
        c += b"\xFF\xE0"
    elif template == "console_print":
        msg_len = len(params["console_msg"].encode("ascii", "ignore"))
        c += b"\x48\x83\xEC\x28"
        c += b"\x48\xC7\xC1\xF5\xFF\xFF\xFF"
        c += b"\x48\xA1" + struct.pack("<Q", iat_va["GetStdHandle"])
        c += b"\xFF\xD0"
        c += b"\x48\x89\xC1"
        c += b"\x48\xBA" + struct.pack("<Q", strings["msg"][1])
        c += b"\x41\xB8" + struct.pack("<I", msg_len)
        c += b"\x4D\x31\xC9"
        c += b"\x48\xC7\x44\x24\x20\x00\x00\x00\x00"
        c += b"\x48\xA1" + struct.pack("<Q", iat_va["WriteFile"])
        c += b"\xFF\xD0"
        c += b"\x48\x83\xC4\x28"
        c += b"\x48\x31\xC9"
        c += b"\x48\xA1" + struct.pack("<Q", iat_va["ExitProcess"])
        c += b"\xFF\xE0"
    elif template == "exit_only":
        c += b"\x48\x83\xEC\x28"
        c += b"\x48\x31\xC9"
        c += b"\x48\xA1" + struct.pack("<Q", iat_va["ExitProcess"])
        c += b"\xFF\xE0"
    return bytes(c)


def build_pe(arch, template, params):
    """
    返回 (data: bytes, info: dict)
    info["api_list"] = [(dll, func), ...]  —— raw_shellcode 模板的 API 表索引顺序
    """
    is64 = (arch == "x64")
    IMAGE_BASE = 0x140000000 if is64 else 0x400000
    SEC_ALIGN = 0x1000
    FILE_ALIGN = 0x200
    THUNK_SIZE = 8 if is64 else 4
    TEXT_RVA = 0x1000
    RDATA_RVA = 0x2000

    tpl = TEMPLATES[template]
    subsystem = tpl["subsystem"]

    # ---------- 合并导入列表 ----------
    if template == "raw_shellcode":
        merged = {}
        all_imports = [("kernel32.dll", ["ExitProcess"])]
        for dll, funcs in params.get("extra_imports", []):
            all_imports.append((dll, funcs))
        for dll, funcs in all_imports:
            key = dll.lower()
            if key not in merged:
                merged[key] = (dll, [])
            for f in funcs:
                if f not in merged[key][1]:
                    merged[key][1].append(f)
        imports_spec = list(merged.values())
    else:
        imports_spec = tpl["imports"]

    # ============ 1. .rdata ============
    rdata = bytearray()

    def r_add(data, al=1):
        while len(rdata) % al:
            rdata.append(0)
        off = len(rdata)
        rdata.extend(data)
        return off

    def rva_of(off):
        return RDATA_RVA + off

    def va_of(off):
        return IMAGE_BASE + RDATA_RVA + off

    n_dlls = len(imports_spec)
    desc_off = r_add(b"\x00" * (20 * (n_dlls + 1)), 4)

    dll_layout = []
    for dll_name, funcs in imports_spec:
        n_thunks = len(funcs) + 1
        int_off = r_add(b"\x00" * (THUNK_SIZE * n_thunks), THUNK_SIZE)
        iat_off = r_add(b"\x00" * (THUNK_SIZE * n_thunks), THUNK_SIZE)
        dll_layout.append({"dll": dll_name, "funcs": funcs,
                           "int_off": int_off, "iat_off": iat_off, "hn": []})

    for d in dll_layout:
        for fn in d["funcs"]:
            hn_off = r_add(b"\x00\x00" + fn.encode("ascii") + b"\x00", 2)
            d["hn"].append((fn, hn_off))
        d["name_off"] = r_add(d["dll"].encode("ascii") + b"\x00")

    for d in dll_layout:
        for i, (fn, hn_off) in enumerate(d["hn"]):
            val = rva_of(hn_off)
            if is64:
                struct.pack_into("<Q", rdata, d["int_off"] + i * 8, val)
                struct.pack_into("<Q", rdata, d["iat_off"] + i * 8, val)
            else:
                struct.pack_into("<I", rdata, d["int_off"] + i * 4, val)
                struct.pack_into("<I", rdata, d["iat_off"] + i * 4, val)

    for i, d in enumerate(dll_layout):
        struct.pack_into("<IIIII", rdata, desc_off + i * 20,
                         rva_of(d["int_off"]), 0, 0,
                         rva_of(d["name_off"]), rva_of(d["iat_off"]))

    # IAT VA 双 key：函数名 & (dll, 函数名)
    iat_va = {}
    for d in dll_layout:
        for i, (fn, _) in enumerate(d["hn"]):
            va = IMAGE_BASE + rva_of(d["iat_off"] + i * THUNK_SIZE)
            iat_va[fn] = va
            iat_va[(d["dll"].lower(), fn)] = va

    strings = {}
    if template == "messagebox":
        off = r_add(params["text"].encode("ascii", "ignore") + b"\x00")
        strings["text"] = (off, va_of(off))
        off = r_add(params["caption"].encode("ascii", "ignore") + b"\x00")
        strings["caption"] = (off, va_of(off))
    elif template == "console_print":
        off = r_add(params["console_msg"].encode("ascii", "ignore") + b"\x00")
        strings["msg"] = (off, va_of(off))

    # ============ 2. .text ============
    api_list = []
    table = bytearray()

    if template == "raw_shellcode":
        # API 表：按用户额外导入的顺序去重
        seen = set()
        for dll, funcs in params.get("extra_imports", []):
            for f in funcs:
                key = (dll.lower(), f)
                if key in seen:
                    continue
                seen.add(key)
                api_list.append((dll, f))

        for dll, f in api_list:
            va = iat_va[(dll.lower(), f)]
            table += struct.pack("<Q" if is64 else "<I", va)

        # preamble：把 API 表地址放入 EBP(x86) / R15(x64)
        preamble = bytearray()
        if is64:
            next_off = len(table) + 7
            disp = -next_off
            preamble += b"\x4C\x8D\x3D" + struct.pack("<i", disp)   # lea r15, [rip+disp]
        else:
            table_va = IMAGE_BASE + TEXT_RVA
            preamble += b"\xBD" + struct.pack("<I", table_va)       # mov ebp, imm32

        code = bytes(table) + bytes(preamble) + params["shellcode"]
        if is64:
            code += b"\x48\x31\xC9"
            code += b"\x48\xA1" + struct.pack("<Q", iat_va[("kernel32.dll", "ExitProcess")])
            code += b"\xFF\xE0"
        else:
            code += b"\x6A\x00"
            code += b"\xFF\x15" + struct.pack("<I", iat_va[("kernel32.dll", "ExitProcess")])
            code += b"\xC3"
    else:
        if is64:
            code = _code_x64(template, iat_va, strings, params)
        else:
            code = _code_x86(template, iat_va, strings, params)

    ep_rva = TEXT_RVA + len(table)

    # ============ 3. 布局 ============
    n_sections = 2
    opt_size = 240 if is64 else 224
    headers_base = 0x40 + 4 + 20 + opt_size + n_sections * 40
    size_of_headers = align(headers_base, FILE_ALIGN)

    text_raw = size_of_headers
    text_raw_size = align(len(code), FILE_ALIGN)
    rdata_raw = text_raw + text_raw_size
    rdata_raw_size = align(len(rdata), FILE_ALIGN)
    size_of_image = align(RDATA_RVA + len(rdata), SEC_ALIGN)

    # ============ 4. DOS + COFF ============
    dos = bytearray(0x40)
    struct.pack_into("<H", dos, 0, 0x5A4D)
    struct.pack_into("<I", dos, 0x3C, 0x40)

    machine = 0x8664 if is64 else 0x14C
    characteristics = 0x0022 if is64 else 0x0102
    coff = struct.pack("<HHIIIHH", machine, n_sections, 0, 0, 0, opt_size, characteristics)

    # ============ 5. 可选头 ============
    if is64:
        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x20B, 0, 0,
            text_raw_size, rdata_raw_size, 0,
            ep_rva, TEXT_RVA,
            IMAGE_BASE,
            SEC_ALIGN, FILE_ALIGN,
            4, 0, 0, 0, 4, 0,
            0,
            size_of_image, size_of_headers, 0,
            subsystem, 0,
            0x100000, 0x1000, 0x100000, 0x1000,
            0, 16,
        )
    else:
        opt = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x10B, 0, 0,
            text_raw_size, rdata_raw_size, 0,
            ep_rva, TEXT_RVA, RDATA_RVA,
            IMAGE_BASE, SEC_ALIGN, FILE_ALIGN,
            4, 0, 0, 0, 4, 0,
            0,
            size_of_image, size_of_headers, 0,
            subsystem, 0,
            0x100000, 0x1000, 0x100000, 0x1000,
            0, 16,
        )

    dd = bytearray(16 * 8)
    struct.pack_into("<II", dd, 8, rva_of(desc_off), 20 * (n_dlls + 1))
    opt += bytes(dd)
    assert len(opt) == opt_size, (len(opt), opt_size)

    # ============ 6. 节表 ============
    def sec_hdr(name, vs, va, rs, rp, ch):
        return struct.pack("<8sIIIIIIHHI",
                           name.ljust(8, b"\x00"), vs, va, rs, rp,
                           0, 0, 0, 0, ch)

    headers = bytes(dos) + b"PE\x00\x00" + coff + opt
    headers += sec_hdr(b".text", len(code), TEXT_RVA, text_raw_size, text_raw, 0x60000020)
    headers += sec_hdr(b".rdata", len(rdata), RDATA_RVA, rdata_raw_size, rdata_raw, 0x40000040)
    headers = headers.ljust(size_of_headers, b"\x00")

    data = (headers
            + bytes(code).ljust(text_raw_size, b"\x00")
            + bytes(rdata).ljust(rdata_raw_size, b"\x00"))
    return data, {"api_list": api_list}


# ============================================================
# UI
# ============================================================
class BuildTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self._build_ui()

    def _build_ui(self):
        top = ttk.LabelFrame(self, text="架构与模板")
        top.pack(fill="x", padx=8, pady=4)

        ttk.Label(top, text="架构:").grid(row=0, column=0, sticky="e", padx=4, pady=3)
        self.arch_var = tk.StringVar(value="x86")
        arch_frame = ttk.Frame(top)
        arch_frame.grid(row=0, column=1, sticky="w", padx=4)
        ttk.Radiobutton(arch_frame, text="x86 (PE32)", value="x86",
                        variable=self.arch_var, command=self._on_change).pack(side="left", padx=2)
        ttk.Radiobutton(arch_frame, text="x64 (PE32+)", value="x64",
                        variable=self.arch_var, command=self._on_change).pack(side="left", padx=2)

        ttk.Label(top, text="模板:").grid(row=1, column=0, sticky="e", padx=4, pady=3)
        self.tpl_var = tk.StringVar(value="messagebox")
        values = [f"{k} — {v['name']}" for k, v in TEMPLATES.items()]
        self.tpl_combo = ttk.Combobox(top, values=values, state="readonly", width=46)
        self.tpl_combo.current(0)
        self.tpl_combo.grid(row=1, column=1, sticky="w", padx=4)
        self.tpl_combo.bind("<<ComboboxSelected>>", self._on_change)

        self.param_frame = ttk.LabelFrame(self, text="模板参数")
        self.param_frame.pack(fill="x", padx=8, pady=4)
        self.param_widgets = {}
        self._build_param_widgets()

        btn = ttk.Frame(self)
        btn.pack(fill="x", padx=8, pady=4)
        ttk.Button(btn, text="生成并保存...", command=self.do_build).pack(side="left")

        self.log_text = ScrolledText(self, height=14)
        self.log_text.pack(fill="both", expand=True, padx=8, pady=4)

    def _current_template(self):
        return self.tpl_combo.get().split(" — ")[0]

    def _build_param_widgets(self):
        for w in self.param_frame.winfo_children():
            w.destroy()
        self.param_widgets = {}
        tpl = self._current_template()
        params = TEMPLATES[tpl]["params"]
        row = 0

        if "caption" in params:
            ttk.Label(self.param_frame, text="标题:").grid(row=row, column=0, sticky="e", padx=4, pady=2)
            v = tk.StringVar(value="Hello")
            ttk.Entry(self.param_frame, textvariable=v, width=56).grid(row=row, column=1, padx=4, pady=2, sticky="w")
            self.param_widgets["caption"] = v
            row += 1
        if "text" in params:
            ttk.Label(self.param_frame, text="消息:").grid(row=row, column=0, sticky="e", padx=4, pady=2)
            v = tk.StringVar(value="PE built by struct, running natively.")
            ttk.Entry(self.param_frame, textvariable=v, width=56).grid(row=row, column=1, padx=4, pady=2, sticky="w")
            self.param_widgets["text"] = v
            row += 1
        if "console_msg" in params:
            ttk.Label(self.param_frame, text="控制台输出:").grid(row=row, column=0, sticky="e", padx=4, pady=2)
            v = tk.StringVar(value="Hello from a natively-built PE!\\r\\n")
            ttk.Entry(self.param_frame, textvariable=v, width=56).grid(row=row, column=1, padx=4, pady=2, sticky="w")
            self.param_widgets["console_msg"] = v
            row += 1
        if "shellcode_hex" in params:
            ttk.Label(self.param_frame, text="Shellcode (hex):").grid(row=row, column=0, sticky="ne", padx=4, pady=2)
            self.sc_text = tk.Text(self.param_frame, height=4, width=56)
            self.sc_text.grid(row=row, column=1, padx=4, pady=2, sticky="w")
            ttk.Label(self.param_frame, text="空格/换行/注释(;)均可用，非 hex 字符会被忽略。",
                      foreground="gray").grid(row=row + 1, column=1, sticky="w", padx=4)
            row += 2
        if "extra_imports" in params:
            ttk.Label(self.param_frame, text="额外导入 (每行 dll!func):").grid(
                row=row, column=0, sticky="ne", padx=4, pady=2)
            self.imports_text = tk.Text(self.param_frame, height=4, width=56)
            self.imports_text.grid(row=row, column=1, padx=4, pady=2, sticky="w")
            self.imports_text.insert("1.0", "user32.dll!MessageBoxA\n")
            ttk.Label(self.param_frame,
                      text="入口时 EBP(x86) / R15(x64) = API 表地址；"
                           "call [ebp+4*i] / call qword [r15+8*i]。",
                      foreground="gray").grid(row=row + 1, column=1, sticky="w", padx=4)
            row += 2

        if not params:
            ttk.Label(self.param_frame, text="(该模板无参数)",
                      foreground="gray").grid(row=0, column=0, sticky="w", padx=4, pady=2)

    def _on_change(self, event=None):
        self._build_param_widgets()

    def log(self, msg):
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")

    def do_build(self):
        tpl = self._current_template()
        arch = self.arch_var.get()
        params = {}

        if "caption" in self.param_widgets:
            params["caption"] = self.param_widgets["caption"].get()
        if "text" in self.param_widgets:
            params["text"] = self.param_widgets["text"].get()
        if "console_msg" in self.param_widgets:
            raw = self.param_widgets["console_msg"].get()
            params["console_msg"] = raw.replace("\\r", "\r").replace("\\n", "\n")

        if tpl == "raw_shellcode":
            text = self.sc_text.get("1.0", "end")
            text = "\n".join(line.split(";")[0] for line in text.splitlines())
            clean = "".join(c for c in text if c in "0123456789abcdefABCDEF")
            if len(clean) % 2:
                self.log("Shellcode hex 长度为奇数，已截断末位。")
                clean = clean[:-1]
            try:
                params["shellcode"] = bytes.fromhex(clean) if clean else b""
            except ValueError:
                messagebox.showerror("错误", "Shellcode 不是合法 hex")
                return

            imports_raw = self.imports_text.get("1.0", "end")
            merged = {}
            for line in imports_raw.splitlines():
                line = line.split("#")[0].strip()
                if not line:
                    continue
                if "!" not in line:
                    self.log(f"跳过无效导入行 (缺少 !): {line}")
                    continue
                dll, func = line.split("!", 1)
                dll = dll.strip()
                func = func.strip()
                if not dll or not func:
                    self.log(f"跳过无效导入行: {line}")
                    continue
                merged.setdefault(dll, [])
                if func not in merged[dll]:
                    merged[dll].append(func)
            params["extra_imports"] = list(merged.items())

        out = filedialog.asksaveasfilename(
            defaultextension=".exe",
            filetypes=[("Windows PE", "*.exe"), ("All", "*.*")],
        )
        if not out:
            return

        try:
            data, info = build_pe(arch, tpl, params)
            with open(out, "wb") as f:
                f.write(data)
            self.log(f"生成成功: {out}  ({len(data)} 字节)")
            self.log(f"  架构: {arch}  模板: {tpl}  子系统: {TEMPLATES[tpl]['subsystem']}")
            if info.get("api_list"):
                self.log("  API 表索引 (shellcode 用 [EBP+4*i] / [R15+8*i]):")
                for i, (dll, f) in enumerate(info["api_list"]):
                    self.log(f"    [{i}] {dll}!{f}")
            messagebox.showinfo("完成", f"已生成: {out}\n大小: {len(data)} 字节")
        except Exception as e:
            self.log(f"生成失败: {e!r}")
            messagebox.showerror("错误", str(e))


class App:
    def __init__(self, root):
        root.title("PE 构造器 — 纯 struct / x86 · x64 / 可调用任意 API")
        root.geometry("900x720")
        BuildTab(root).pack(fill="both", expand=True)


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
