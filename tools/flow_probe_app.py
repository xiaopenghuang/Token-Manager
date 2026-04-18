from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.flow_probe_core import FlowProbe, ProbeOptions, TargetInfo, ensure_probe_dir, load_targets


def _runtime_base_dir() -> Path:
    if getattr(sys, "frozen", False) and getattr(sys, "_MEIPASS", None):
        return Path(sys._MEIPASS)
    return PROJECT_ROOT


def _apply_window_icon(root: tk.Tk) -> None:
    base_dir = _runtime_base_dir()
    ico_candidates = [
        base_dir / "build_assets" / "flow_probe.ico",
        base_dir / "ico" / "flow_probe.ico",
        base_dir / "build_assets" / "openai.ico",
        base_dir / "ico" / "openai.ico",
    ]
    png_candidates = [
        base_dir / "ico" / "flow_probe.png",
        base_dir / "ico" / "openai.png",
    ]

    for ico_path in ico_candidates:
        if not ico_path.exists():
            continue
        try:
            root.iconbitmap(default=str(ico_path))
            return
        except Exception:
            pass

    for png_path in png_candidates:
        if not png_path.exists():
            continue
        try:
            image = tk.PhotoImage(file=str(png_path))
            root._window_icon_ref = image  # type: ignore[attr-defined]
            root.iconphoto(True, image)
            return
        except Exception:
            pass


class FlowProbeApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Flow Probe Studio")
        self.root.geometry("1260x860")
        self.root.minsize(1100, 720)

        self.targets: list[TargetInfo] = []
        self.target_id_by_label: dict[str, str] = {}
        self.probe: FlowProbe | None = None
        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self.event_queue: "queue.Queue[dict[str, object]]" = queue.Queue()

        self.debug_port_var = tk.IntVar(value=9222)
        self.target_var = tk.StringVar(value="")
        self.filter_var = tk.StringVar(value=".*")
        self.capture_body_var = tk.BooleanVar(value=True)
        self.output_dir_var = tk.StringVar(value=str(ensure_probe_dir()))
        self.browser_path_var = tk.StringVar(value=self._detect_browser_path())
        self.start_url_var = tk.StringVar(value="about:blank")
        self.status_var = tk.StringVar(value="就绪")
        self.session_var = tk.StringVar(value="未开始")
        self.counts_var = tk.StringVar(value="请求 0  响应 0  导航 0")

        self.request_count = 0
        self.response_count = 0
        self.navigation_count = 0

        self._configure_styles()
        self._build_ui()
        self.root.after(150, self._poll_queues)
        self.refresh_targets(show_dialog=False)

    def _configure_styles(self) -> None:
        palette = {
            "bg": "#eef4f6",
            "card": "#fbfdfe",
            "alt": "#f4f8fa",
            "text": "#1f3139",
            "muted": "#5f727c",
            "border": "#d7e2e8",
            "primary": "#0f766e",
            "primary_hover": "#115e59",
        }
        self.palette = palette
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        self.root.configure(bg=palette["bg"])
        style.configure(".", font=("Microsoft YaHei UI", 10), background=palette["bg"], foreground=palette["text"])
        style.configure("TFrame", background=palette["bg"])
        style.configure("Card.TFrame", background=palette["card"])
        style.configure("TLabel", background=palette["bg"], foreground=palette["text"])
        style.configure("Card.TLabel", background=palette["card"], foreground=palette["text"])
        style.configure("Muted.TLabel", background=palette["card"], foreground=palette["muted"])
        style.configure(
            "Card.TLabelframe",
            background=palette["card"],
            borderwidth=1,
            relief="solid",
            bordercolor=palette["border"],
            lightcolor=palette["border"],
            darkcolor=palette["border"],
        )
        style.configure(
            "Card.TLabelframe.Label",
            background=palette["card"],
            foreground=palette["text"],
            font=("Microsoft YaHei UI", 10, "bold"),
        )
        style.configure(
            "TButton",
            padding=(10, 7),
            background=palette["alt"],
            foreground=palette["text"],
            bordercolor=palette["border"],
            lightcolor=palette["border"],
            darkcolor=palette["border"],
        )
        style.configure(
            "Primary.TButton",
            padding=(10, 7),
            background=palette["primary"],
            foreground="#ffffff",
            bordercolor=palette["primary"],
            lightcolor=palette["primary"],
            darkcolor=palette["primary"],
        )
        style.map("Primary.TButton", background=[("active", palette["primary_hover"])], foreground=[("active", "#ffffff")])
        style.configure("Treeview", background=palette["card"], fieldbackground=palette["card"], foreground=palette["text"], rowheight=30)
        style.configure("Treeview.Heading", background=palette["alt"], foreground=palette["text"], font=("Microsoft YaHei UI", 10, "bold"))
        style.configure("TCombobox", fieldbackground=palette["card"], background=palette["card"])
        style.configure("TEntry", fieldbackground=palette["card"])

    def _detect_browser_path(self) -> str:
        candidates: list[Path] = []
        local_appdata = Path(os.environ.get("LOCALAPPDATA") or "")
        program_files = Path(os.environ.get("PROGRAMFILES") or "")
        program_files_x86 = Path(os.environ.get("PROGRAMFILES(X86)") or "")
        for base, relative in (
            (local_appdata, r"Google\Chrome\Application\chrome.exe"),
            (program_files, r"Google\Chrome\Application\chrome.exe"),
            (program_files_x86, r"Google\Chrome\Application\chrome.exe"),
            (local_appdata, r"Microsoft\Edge\Application\msedge.exe"),
            (program_files, r"Microsoft\Edge\Application\msedge.exe"),
            (program_files_x86, r"Microsoft\Edge\Application\msedge.exe"),
        ):
            if str(base):
                candidates.append(base / relative)
        for path in candidates:
            if path.exists():
                return str(path)
        return ""

    def _debug_profile_dir(self) -> Path:
        profile_dir = ensure_probe_dir() / f"browser_profile_{int(self.debug_port_var.get())}"
        profile_dir.mkdir(parents=True, exist_ok=True)
        return profile_dir

    def _build_debug_browser_command(self) -> list[str]:
        browser_path = self.browser_path_var.get().strip()
        if not browser_path:
            raise RuntimeError("还没找到浏览器路径")
        start_url = self.start_url_var.get().strip() or "about:blank"
        profile_dir = self._debug_profile_dir()
        return [
            browser_path,
            f"--remote-debugging-port={int(self.debug_port_var.get())}",
            "--remote-allow-origins=*",
            f"--user-data-dir={profile_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            start_url,
        ]

    def _build_ui(self) -> None:
        shell = ttk.Frame(self.root, padding=14)
        shell.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(shell, style="Card.TFrame", padding=(14, 12))
        header.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(header, text="Flow Probe Studio", style="Card.TLabel", font=("Microsoft YaHei UI", 20, "bold")).pack(side=tk.LEFT)
        ttk.Label(header, textvariable=self.status_var, style="Muted.TLabel").pack(side=tk.RIGHT)

        main = ttk.PanedWindow(shell, orient=tk.VERTICAL)
        main.pack(fill=tk.BOTH, expand=True)

        top = ttk.Frame(main)
        top.columnconfigure(0, weight=1)
        top.rowconfigure(1, weight=1)
        main.add(top, weight=3)

        controls = ttk.LabelFrame(top, text="监听设置", padding=10, style="Card.TLabelframe")
        controls.grid(row=0, column=0, sticky="ew")
        for idx in range(6):
            controls.columnconfigure(idx, weight=1)

        ttk.Label(controls, text="调试端口", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=3, pady=3)
        ttk.Spinbox(controls, from_=1, to=65535, textvariable=self.debug_port_var, width=8).grid(row=0, column=1, sticky="w", padx=3, pady=3)
        ttk.Button(controls, text="刷新页签", command=self.refresh_targets).grid(row=0, column=2, sticky="ew", padx=3, pady=3)
        ttk.Button(controls, text="输出目录", command=self.choose_output_dir).grid(row=0, column=3, sticky="ew", padx=3, pady=3)
        ttk.Checkbutton(controls, text="抓响应体", variable=self.capture_body_var).grid(row=0, column=4, sticky="w", padx=3, pady=3)
        ttk.Button(controls, text="开始监听", command=self.start_probe, style="Primary.TButton").grid(row=0, column=5, sticky="ew", padx=3, pady=3)

        ttk.Label(controls, text="目标页签", style="Card.TLabel").grid(row=1, column=0, sticky="w", padx=3, pady=3)
        self.target_combo = ttk.Combobox(controls, textvariable=self.target_var, state="readonly")
        self.target_combo.grid(row=1, column=1, columnspan=3, sticky="ew", padx=3, pady=3)
        ttk.Button(controls, text="启动调试浏览器", command=self.launch_debug_browser).grid(row=1, column=4, sticky="ew", padx=3, pady=3)
        ttk.Button(controls, text="停止", command=self.stop_probe).grid(row=1, column=5, sticky="ew", padx=3, pady=3)

        ttk.Label(controls, text="浏览器路径", style="Card.TLabel").grid(row=2, column=0, sticky="w", padx=3, pady=3)
        ttk.Entry(controls, textvariable=self.browser_path_var).grid(row=2, column=1, columnspan=3, sticky="ew", padx=3, pady=3)
        ttk.Button(controls, text="选择浏览器", command=self.choose_browser_path).grid(row=2, column=4, sticky="ew", padx=3, pady=3)
        ttk.Button(controls, text="清空日志", command=self.clear_logs).grid(row=2, column=5, sticky="ew", padx=3, pady=3)

        ttk.Label(controls, text="起始 URL", style="Card.TLabel").grid(row=3, column=0, sticky="w", padx=3, pady=3)
        ttk.Entry(controls, textvariable=self.start_url_var).grid(row=3, column=1, columnspan=5, sticky="ew", padx=3, pady=3)

        ttk.Label(controls, text="过滤正则", style="Card.TLabel").grid(row=4, column=0, sticky="w", padx=3, pady=3)
        ttk.Entry(controls, textvariable=self.filter_var).grid(row=4, column=1, columnspan=5, sticky="ew", padx=3, pady=3)
        ttk.Label(controls, textvariable=self.session_var, style="Muted.TLabel").grid(row=5, column=0, columnspan=4, sticky="w", padx=3, pady=(6, 0))
        ttk.Label(controls, textvariable=self.counts_var, style="Muted.TLabel").grid(row=5, column=4, columnspan=2, sticky="e", padx=3, pady=(6, 0))

        center = ttk.PanedWindow(top, orient=tk.HORIZONTAL)
        center.grid(row=1, column=0, sticky="nsew", pady=(10, 0))

        target_card = ttk.LabelFrame(center, text="可附着页签", padding=8, style="Card.TLabelframe")
        target_card.columnconfigure(0, weight=1)
        target_card.rowconfigure(0, weight=1)
        self.target_tree = ttk.Treeview(target_card, columns=("title", "url"), show="headings")
        self.target_tree.heading("title", text="标题")
        self.target_tree.heading("url", text="URL")
        self.target_tree.column("title", width=280, stretch=False)
        self.target_tree.column("url", width=520, stretch=True)
        target_scroll = ttk.Scrollbar(target_card, orient=tk.VERTICAL, command=self.target_tree.yview)
        self.target_tree.configure(yscrollcommand=target_scroll.set)
        self.target_tree.grid(row=0, column=0, sticky="nsew")
        target_scroll.grid(row=0, column=1, sticky="ns")
        self.target_tree.bind("<<TreeviewSelect>>", self.on_target_selected)

        log_card = ttk.LabelFrame(center, text="实时日志", padding=8, style="Card.TLabelframe")
        log_card.columnconfigure(0, weight=1)
        log_card.rowconfigure(0, weight=1)
        self.log_text = scrolledtext.ScrolledText(
            log_card,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg=self.palette["card"],
            fg=self.palette["text"],
            relief="flat",
            insertbackground=self.palette["text"],
            highlightthickness=1,
            highlightbackground=self.palette["border"],
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")

        center.add(target_card, weight=2)
        center.add(log_card, weight=3)

        bottom = ttk.LabelFrame(main, text="事件预览", padding=8, style="Card.TLabelframe")
        bottom.columnconfigure(0, weight=1)
        bottom.rowconfigure(0, weight=1)
        self.event_text = scrolledtext.ScrolledText(
            bottom,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg=self.palette["card"],
            fg=self.palette["text"],
            relief="flat",
            insertbackground=self.palette["text"],
            highlightthickness=1,
            highlightbackground=self.palette["border"],
        )
        self.event_text.grid(row=0, column=0, sticky="nsew")
        main.add(bottom, weight=2)

    def choose_output_dir(self) -> None:
        selected = filedialog.askdirectory(title="选择输出目录", initialdir=self.output_dir_var.get().strip() or ".")
        if selected:
            self.output_dir_var.set(selected)

    def choose_browser_path(self) -> None:
        selected = filedialog.askopenfilename(
            title="选择浏览器程序",
            initialdir=str(Path(self.browser_path_var.get()).parent) if self.browser_path_var.get().strip() else ".",
            filetypes=[("浏览器程序", "*.exe"), ("所有文件", "*.*")],
        )
        if selected:
            self.browser_path_var.set(selected)

    def _friendly_target_error(self, exc: Exception) -> str:
        port = int(self.debug_port_var.get())
        text = str(exc)
        if "127.0.0.1" in text and f"port={port}" in text:
            try:
                command_parts = self._build_debug_browser_command()
                command = " ".join(f'"{part}"' if " " in part else part for part in command_parts)
            except Exception:
                command = f"<浏览器路径> --remote-debugging-port={port} --remote-allow-origins=* --user-data-dir=<独立目录>"
            return (
                f"当前没有调试浏览器在监听 {port} 端口。\n\n"
                f"点一下“启动调试浏览器”就行。\n"
                f"也可以手动执行下面这条命令。\n\n{command}"
            )
        return text

    def launch_debug_browser(self) -> None:
        try:
            command = self._build_debug_browser_command()
        except Exception as exc:
            messagebox.showerror("启动失败", str(exc), parent=self.root)
            return
        try:
            subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
        except Exception as exc:
            messagebox.showerror("启动失败", str(exc), parent=self.root)
            return
        self.status_var.set(f"已启动调试浏览器 {int(self.debug_port_var.get())}")
        self._log("已启动调试浏览器")
        self.root.after(1800, lambda: self.refresh_targets(show_dialog=False))

    def refresh_targets(self, *, show_dialog: bool = True) -> None:
        try:
            targets = load_targets(int(self.debug_port_var.get()))
        except Exception as exc:
            self.status_var.set("未连接调试浏览器")
            self.targets = []
            self.target_id_by_label.clear()
            self.target_var.set("")
            self.target_combo["values"] = []
            for item in self.target_tree.get_children():
                self.target_tree.delete(item)
            if show_dialog:
                messagebox.showerror("页签刷新失败", self._friendly_target_error(exc), parent=self.root)
            return
        self.targets = targets
        labels: list[str] = []
        self.target_id_by_label.clear()
        for item in self.target_tree.get_children():
            self.target_tree.delete(item)
        for item in targets:
            label = f"{item.title or '(无标题)'} | {item.url}"
            labels.append(label)
            self.target_id_by_label[label] = item.id
            tree_id = item.id or label
            self.target_tree.insert("", tk.END, iid=tree_id, values=(item.title or "(无标题)", item.url))
        self.target_combo["values"] = labels
        if labels and not self.target_var.get():
            self.target_var.set(labels[0])
        self.status_var.set(f"已加载页签 {len(targets)}")

    def on_target_selected(self, _event=None) -> None:
        selected = self.target_tree.selection()
        if not selected:
            return
        target_id = selected[0]
        for item in self.targets:
            if item.id == target_id:
                self.target_var.set(f"{item.title or '(无标题)'} | {item.url}")
                break

    def _log(self, message: str) -> None:
        self.log_queue.put(message)

    def _on_event(self, payload: dict[str, object]) -> None:
        self.event_queue.put(payload)

    def start_probe(self) -> None:
        if self.probe is not None:
            messagebox.showinfo("提示", "当前已有监听在运行", parent=self.root)
            return
        label = self.target_var.get().strip()
        target_id = self.target_id_by_label.get(label, "")
        self.request_count = 0
        self.response_count = 0
        self.navigation_count = 0
        self.counts_var.set("请求 0  响应 0  导航 0")
        self.event_text.delete("1.0", tk.END)

        options = ProbeOptions(
            debug_port=int(self.debug_port_var.get()),
            target_id=target_id,
            filter_pattern=self.filter_var.get().strip() or ".*",
            output_dir=Path(self.output_dir_var.get().strip() or ensure_probe_dir()),
            capture_response_body=bool(self.capture_body_var.get()),
            output_prefix="flow_probe_studio",
        )
        self.probe = FlowProbe(options, log_fn=self._log, event_fn=self._on_event)
        try:
            prepared = self.probe.prepare()
        except Exception as exc:
            self.probe = None
            messagebox.showerror("启动失败", str(exc), parent=self.root)
            return
        self.session_var.set(f"会话 {prepared['trace_path']}")
        self.status_var.set("监听中")
        self.probe.start_background()

    def stop_probe(self) -> None:
        if self.probe is None:
            return
        self.probe.stop()
        self.probe.join(2)
        self.probe = None
        self.status_var.set("已停止")

    def clear_logs(self) -> None:
        self.log_text.delete("1.0", tk.END)
        self.event_text.delete("1.0", tk.END)

    def _poll_queues(self) -> None:
        while not self.log_queue.empty():
            message = self.log_queue.get_nowait()
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.see(tk.END)
        while not self.event_queue.empty():
            payload = self.event_queue.get_nowait()
            kind = str(payload.get("kind") or "")
            if kind == "request":
                self.request_count += 1
            elif kind == "response":
                self.response_count += 1
            elif kind == "frame_navigated":
                self.navigation_count += 1
            self.counts_var.set(f"请求 {self.request_count}  响应 {self.response_count}  导航 {self.navigation_count}")
            self.event_text.delete("1.0", tk.END)
            self.event_text.insert("1.0", json.dumps(payload, ensure_ascii=False, indent=2))
        self.root.after(150, self._poll_queues)


def main() -> int:
    root = tk.Tk()
    _apply_window_icon(root)
    app = FlowProbeApp(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.stop_probe(), root.destroy()))
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
