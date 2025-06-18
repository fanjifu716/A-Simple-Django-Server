import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from tkinter.scrolledtext import ScrolledText
import os
import subprocess
import sys
import webbrowser
import threading
from datetime import datetime
import logging
import ast
import shutil
import queue
import socket
import time

# 设置日志记录
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(f"logs/django_manager_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class DjangoProjectManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Django 项目管理工具")
        self.root.geometry("900x650")
        self.root.minsize(800, 600)

        # 项目状态变量
        self.project_path = None
        self.installed_packages = {}
        self.third_party_libs = []
        self.project_modules = set()
        self.stdlib_modules = set(sys.stdlib_module_names) if hasattr(sys, 'stdlib_module_names') else set()
        self.server_process = None
        self.log_queue = queue.Queue()
        self.lib_files = {}  # 库与文件的映射关系 {库名: [文件路径列表]}

        # 配置样式
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Arial", 10))
        self.style.configure("Treeview", font=("Arial", 9))
        self.style.configure("Treeview.Heading", font=("Arial", 9, "bold"))
        self.style.configure("Status.TLabel", background="#f0f0f0", relief="sunken", padding=5)

        self.create_widgets()
        self.root.after(100, self.process_log_queue)

    def create_widgets(self):
        """创建界面组件"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 项目信息部分
        info_frame = ttk.LabelFrame(main_frame, text="项目信息", padding="5")
        info_frame.pack(fill=tk.X, pady=5)

        self.project_var = tk.StringVar(value="未选择项目")
        ttk.Label(info_frame, textvariable=self.project_var, font=("Arial", 9)).pack(side=tk.LEFT, padx=5)

        # 工具栏
        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=10)

        # 按钮配置：文本，命令，颜色
        button_config = [
            ("创建新项目", self.create_project, "#4CAF50"),
            ("打开现有项目", self.open_project, "#2196F3"),
            ("检查并安装依赖", self.check_and_install_deps, "#FF9800"),
            ("扫描第三方库", self.scan_third_party_libs, "#9C27B0"),
            ("运行项目", self.run_project, "#E91E63"),
            ("创建虚拟环境", self.create_venv, "#009688"),
            ("停止服务器", self.stop_server, "#F44336"),
            ("文件结构", self.generate_file_tree, "#607D8B")
        ]

        for text, command, color in button_config:
            btn = ttk.Button(toolbar, text=text, command=command)
            btn.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # 状态栏
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=5)

        self.status_var = tk.StringVar(value="准备就绪")
        status_label = ttk.Label(status_frame, textvariable=self.status_var,
                                 style="Status.TLabel", anchor=tk.W)
        status_label.pack(fill=tk.X, ipady=2)

        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=2)

        # 日志输出
        log_frame = ttk.LabelFrame(main_frame, text="操作日志", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.log_text = ScrolledText(log_frame, height=20, font=("Courier New", 9), wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)

        # 配置日志标签样式
        self.log_text.tag_config("INFO", foreground="black")
        self.log_text.tag_config("DEBUG", foreground="gray")
        self.log_text.tag_config("WARNING", foreground="orange")
        self.log_text.tag_config("ERROR", foreground="red")
        self.log_text.tag_config("SUCCESS", foreground="green")

    def log_message(self, message, level="INFO"):
        """将消息放入队列以便线程安全显示"""
        self.log_queue.put((message, level))

    def process_log_queue(self):
        """处理日志队列中的消息"""
        try:
            while True:
                try:
                    message, level = self.log_queue.get_nowait()
                    self.log_text.config(state=tk.NORMAL)
                    self.log_text.insert(
                        tk.END,
                        f"{datetime.now().strftime('%H:%M:%S')} - {level} - {message}\n",
                        level
                    )
                    self.log_text.config(state=tk.DISABLED)
                    self.log_text.see(tk.END)

                    # 同时记录到文件
                    logger_method = {
                        "DEBUG": logger.debug,
                        "WARNING": logger.warning,
                        "ERROR": logger.error,
                        "SUCCESS": logger.info
                    }.get(level, logger.info)

                    logger_method(message)
                except queue.Empty:
                    break
        finally:
            self.root.after(100, self.process_log_queue)

    def update_progress(self, value, max_value=100):
        """更新进度条"""
        self.progress_var.set(value)
        if value >= max_value:
            self.progress_bar.configure(mode='determinate')
        else:
            self.progress_bar.configure(mode='determinate')

    def get_venv_python(self):
        """查找虚拟环境中的Python可执行文件"""
        if not self.project_path:
            self.log_message("未选择项目，无法获取虚拟环境", "WARNING")
            return sys.executable

        venv_names = ["venv", ".venv", "env"]
        for venv_name in venv_names:
            for base_path in [self.project_path, os.path.dirname(self.project_path)]:
                venv_path = os.path.join(base_path, venv_name)
                if os.name == "nt":
                    venv_python = os.path.join(venv_path, "Scripts", "python.exe")
                else:
                    venv_python = os.path.join(venv_path, "bin", "python")

                if os.path.exists(venv_python):
                    self.log_message(f"找到虚拟环境: {venv_python}", "DEBUG")
                    return venv_python

        self.log_message("未找到虚拟环境，将使用系统Python。建议点击'创建虚拟环境'按钮。", "WARNING")
        return sys.executable

    def create_venv(self):
        """创建虚拟环境（支持指定Django版本）"""
        if not self.project_path:
            messagebox.showerror("错误", "请先打开一个Django项目")
            return

        # 获取用户输入的Django版本（可选）
        django_version = simpledialog.askstring(
            "指定Django版本",
            "请输入Django版本（留空使用最新版）：",
            initialvalue=""
        )

        def task():
            self.status_var.set("正在创建虚拟环境...")
            self.update_progress(0)
            try:
                venv_name = "venv"
                venv_path = os.path.join(self.project_path, venv_name)

                # 检查虚拟环境是否存在
                if os.path.exists(venv_path):
                    confirm = messagebox.askyesno(
                        "确认",
                        f"虚拟环境已存在：{venv_path}\n是否重新创建？"
                    )
                    if not confirm:
                        self.log_message("用户取消虚拟环境创建", "INFO")
                        self.status_var.set("虚拟环境创建取消")
                        return

                    # 跨平台删除旧虚拟环境
                    shutil.rmtree(venv_path, ignore_errors=True)
                    self.log_message(f"已删除旧虚拟环境: {venv_path}", "INFO")

                # 创建新虚拟环境
                self.log_message(f"创建虚拟环境在: {venv_path}", "INFO")
                self.update_progress(20)
                subprocess.check_call([sys.executable, "-m", "venv", venv_path])
                self.log_message("虚拟环境创建成功", "SUCCESS")
                self.update_progress(40)

                venv_python = self.get_venv_python()

                # 升级pip
                self.log_message("正在升级pip...", "INFO")
                self.update_progress(50)
                subprocess.check_call([venv_python, "-m", "pip", "install", "--upgrade", "pip"])
                self.log_message("pip已升级", "SUCCESS")
                self.update_progress(60)

                # 安装指定版本的Django
                install_cmd = [venv_python, "-m", "pip", "install", "django"]
                if django_version:
                    install_cmd.append(f"django=={django_version}")
                    self.log_message(f"正在安装Django {django_version}...", "INFO")
                else:
                    self.log_message("正在安装最新版Django...", "INFO")

                subprocess.check_call(install_cmd)
                self.log_message(f"Django {'v' + django_version if django_version else '最新版'} 已安装", "SUCCESS")
                self.update_progress(100)

                self.status_var.set("虚拟环境创建完成")
            except Exception as e:
                self.log_message(f"创建虚拟环境失败: {str(e)}", "ERROR")
                self.status_var.set(f"错误: {str(e)}")
                messagebox.showerror("错误", f"创建虚拟环境失败: {str(e)}")
            finally:
                self.update_progress(0)

        threading.Thread(target=task, daemon=True).start()

    def create_project(self):
        """创建新Django项目"""
        project_name = simpledialog.askstring("创建新项目", "请输入项目名称：")
        if not project_name:
            self.status_var.set("项目创建取消")
            return

        project_dir = filedialog.askdirectory(title="选择项目保存位置")
        if not project_dir:
            self.status_var.set("项目创建取消")
            return

        project_path = os.path.join(project_dir, project_name)

        def task():
            self.status_var.set(f"正在创建项目: {project_name}...")
            self.update_progress(0)
            try:
                # 创建项目目录
                self.log_message(f"创建项目目录: {project_path}", "INFO")
                os.makedirs(project_path, exist_ok=True)
                self.update_progress(10)

                # 创建虚拟环境
                venv_path = os.path.join(project_path, "venv")
                self.log_message(f"创建虚拟环境在: {venv_path}", "INFO")
                self.update_progress(20)
                subprocess.check_call([sys.executable, "-m", "venv", venv_path])
                self.log_message("虚拟环境创建成功", "SUCCESS")
                self.update_progress(30)

                # 获取虚拟环境Python路径
                if os.name == "nt":
                    venv_python = os.path.join(venv_path, "Scripts", "python.exe")
                else:
                    venv_python = os.path.join(venv_path, "bin", "python")

                self.log_message(f"使用Python: {venv_python}", "DEBUG")

                # 升级pip
                self.log_message("正在升级pip...", "INFO")
                self.update_progress(40)
                subprocess.check_call([venv_python, "-m", "pip", "install", "--upgrade", "pip"])
                self.log_message("pip已升级", "SUCCESS")
                self.update_progress(50)

                # 安装Django
                self.log_message("正在安装Django...", "INFO")
                self.update_progress(60)
                subprocess.check_call([venv_python, "-m", "pip", "install", "django"])
                self.log_message("Django已安装", "SUCCESS")
                self.update_progress(70)

                # 创建Django项目
                os.chdir(project_path)
                self.log_message(f"创建Django项目: {project_name}", "INFO")
                self.update_progress(80)
                subprocess.check_call([venv_python, "-m", "django", "startproject", project_name])
                self.log_message(f"Django项目 '{project_name}' 创建成功", "SUCCESS")
                self.update_progress(90)

                # 创建静态文件目录
                static_dir = os.path.join(project_path, "static")
                os.makedirs(static_dir, exist_ok=True)
                self.log_message(f"创建静态文件目录: {static_dir}", "INFO")

                self.project_path = project_path
                self.project_var.set(project_path)
                self.log_message(f"项目 '{project_name}' 创建完成", "SUCCESS")
                self.update_progress(100)
                self.status_var.set("项目创建完成")
            except Exception as e:
                self.log_message(f"创建项目失败: {str(e)}", "ERROR")
                self.status_var.set(f"错误: {str(e)}")
                messagebox.showerror("错误", f"创建项目失败: {str(e)}")
            finally:
                self.update_progress(0)

        threading.Thread(target=task, daemon=True).start()

    def open_project(self):
        """打开现有Django项目"""
        project_dir = filedialog.askdirectory(title="选择Django项目文件夹")
        if not project_dir:
            self.status_var.set("项目打开取消")
            return

        # 验证是否为有效的Django项目
        manage_py = os.path.join(project_dir, "manage.py")
        if not os.path.exists(manage_py):
            self.log_message(f"错误: {project_dir} 不是有效的Django项目文件夹（缺少manage.py）", "ERROR")
            self.status_var.set("打开项目失败")
            messagebox.showerror("错误", "请选择包含manage.py的Django项目文件夹")
            return

        self.project_path = project_dir
        self.project_var.set(project_dir)
        self.log_message(f"已打开项目: {project_dir}", "SUCCESS")

        # 检查并创建静态文件目录
        static_dir = os.path.join(project_dir, "static")
        if not os.path.exists(static_dir):
            os.makedirs(static_dir, exist_ok=True)
            self.log_message(f"创建静态文件目录: {static_dir}", "INFO")

        self.status_var.set("项目已加载")

    def scan_third_party_libs(self):
        """扫描项目文件并记录第三方库与文件的映射关系"""
        if not self.project_path:
            messagebox.showerror("错误", "请先打开一个Django项目")
            return

        def task():
            self.status_var.set("正在扫描第三方库...")
            self.update_progress(0)
            self.third_party_libs = []
            self.lib_files = {}
            project_modules = set()

            try:
                # 步骤1: 获取项目内部模块
                self.log_message("识别项目内部包...", "INFO")
                self.update_progress(10)

                for root, dirs, files in os.walk(self.project_path):
                    # 跳过虚拟环境目录
                    if any(name in root for name in ["venv", ".venv", "env"]):
                        continue

                    # 只考虑包含__init__.py的目录作为包
                    if "__init__.py" in files:
                        package_name = os.path.basename(root).lower()
                        if package_name != os.path.basename(self.project_path).lower():
                            project_modules.add(package_name)

                    # 对于Python文件，只添加在包目录中的模块
                    for file in files:
                        if file.endswith(".py") and file != "__init__.py":
                            # 检查父目录是否有__init__.py（是否为包）
                            parent_has_init = "__init__.py" in os.listdir(root)
                            if parent_has_init:
                                module_name = os.path.splitext(file)[0].lower()
                                project_modules.add(module_name)

                self.project_modules = project_modules
                self.log_message(f"项目内部包/模块: {', '.join(project_modules)}", "DEBUG")
                self.update_progress(20)

                # 步骤2: 获取已安装的包
                self.log_message("获取已安装包列表...", "INFO")
                self.update_progress(30)

                venv_python = self.get_venv_python()
                result = subprocess.check_output(
                    [venv_python, "-m", "pip", "list", "--format=freeze"],
                    text=True,
                    encoding="utf-8",
                    errors="replace"
                )

                # 解析已安装包
                self.installed_packages = {}
                for line in result.splitlines():
                    if "==" in line:
                        pkg, version = line.split("==", 1)
                        self.installed_packages[pkg.lower()] = version
                    else:
                        self.installed_packages[line.lower()] = "-"

                self.log_message(f"已安装包: {', '.join(self.installed_packages.keys())}", "DEBUG")
                self.update_progress(40)

                # 步骤3: 扫描所有.py文件
                self.log_message("扫描项目文件...", "INFO")
                self.update_progress(50)

                # 收集所有Python文件
                py_files = []
                for root, _, files in os.walk(self.project_path):
                    if any(name in root for name in ["venv", ".venv", "env"]):
                        continue
                    for file in files:
                        if file.endswith(".py"):
                            py_files.append(os.path.join(root, file))

                total_files = len(py_files)
                scanned_files = 0

                for file_path in py_files:
                    scanned_files += 1
                    progress = 50 + int(40 * (scanned_files / total_files))
                    self.update_progress(progress)

                    # 检查文件大小（限制为2MB）
                    file_size = os.path.getsize(file_path)
                    if file_size > 2 * 1024 * 1024:  # 2MB
                        self.log_message(f"跳过过大文件: {file_path}（大小：{file_size / 1024:.2f}KB）", "WARNING")
                        continue

                    self.log_message(f"扫描文件: {file_path}", "DEBUG")

                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            # 使用AST解析文件内容
                            tree = ast.parse(f.read(), filename=file_path)

                            # 遍历AST节点
                            for node in ast.walk(tree):
                                libs = []
                                if isinstance(node, ast.Import):
                                    libs = [alias.name.split(".")[0] for alias in node.names]
                                elif isinstance(node, ast.ImportFrom):
                                    if node.module:
                                        libs = [node.module.split(".")[0]]

                                # 记录第三方库及其引用文件
                                for lib in libs:
                                    if (lib not in self.stdlib_modules and
                                            lib not in project_modules and
                                            lib not in self.project_modules):

                                        if lib not in self.lib_files:
                                            self.lib_files[lib] = []
                                            self.third_party_libs.append(lib)

                                        if file_path not in self.lib_files[lib]:
                                            self.lib_files[lib].append(file_path)

                    except SyntaxError as e:
                        self.log_message(f"文件语法错误: {file_path}（{e}）", "WARNING")
                    except Exception as e:
                        self.log_message(f"扫描文件时发生错误: {file_path}（{e}）", "ERROR")

                self.update_progress(90)

                # 显示结果
                self.root.after(0, self.display_library_results)
                self.status_var.set("第三方库扫描完成")
                self.update_progress(100)

            except Exception as e:
                self.log_message(f"扫描失败: {str(e)}", "ERROR")
                self.status_var.set(f"扫描错误: {str(e)}")
            finally:
                self.update_progress(0)

        threading.Thread(target=task, daemon=True).start()

    def display_library_results(self):
        """在弹窗中显示库扫描结果"""
        lib_window = tk.Toplevel(self.root)
        lib_window.title("第三方库状态")
        lib_window.geometry("900x500")
        lib_window.minsize(700, 400)

        # 主框架
        main_frame = ttk.Frame(lib_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 带滚动条的树状视图
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        tree_scroll = ttk.Scrollbar(tree_frame)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        columns = ("Library", "Status", "Version", "Used in Project")
        lib_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            yscrollcommand=tree_scroll.set
        )
        tree_scroll.config(command=lib_tree.yview)

        # 配置列
        col_widths = [150, 100, 100, 400]
        for col, width in zip(columns, col_widths):
            lib_tree.heading(col, text=col)
            lib_tree.column(col, width=width, anchor=tk.W)

        lib_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 填充数据
        for lib in self.third_party_libs:
            status = "已安装" if lib.lower() in self.installed_packages else "未安装"
            version = self.installed_packages.get(lib.lower(), "-")
            used_files = [os.path.relpath(f, self.project_path) for f in self.lib_files.get(lib, [])]
            used_in_project = "\n".join(used_files[:5])  # 最多显示5个文件
            if len(used_files) > 5:
                used_in_project += f"\n...等{len(used_files)}个文件"
            lib_tree.insert("", "end", values=(lib, status, version, used_in_project))

        # 操作按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)

        install_btn = ttk.Button(
            button_frame,
            text="安装选中库",
            command=lambda: self.install_selected_library(lib_tree)
        )
        install_btn.pack(side=tk.LEFT, padx=5)

        uninstall_btn = ttk.Button(
            button_frame,
            text="卸载选中库",
            command=lambda: self.uninstall_selected_library(lib_tree)
        )
        uninstall_btn.pack(side=tk.LEFT, padx=5)

        refresh_btn = ttk.Button(
            button_frame,
            text="刷新列表",
            command=self.scan_third_party_libs
        )
        refresh_btn.pack(side=tk.LEFT, padx=5)

        close_btn = ttk.Button(
            button_frame,
            text="关闭",
            command=lib_window.destroy
        )
        close_btn.pack(side=tk.RIGHT, padx=5)

        # 双击事件
        lib_tree.bind("<Double-1>", lambda e: self.on_library_double_click(e, lib_tree))

    def on_library_double_click(self, event, tree):
        """处理库的双击事件"""
        selected = tree.selection()
        if not selected:
            return

        item = selected[0]
        values = tree.item(item, "values")
        if values and values[1] == "未安装":
            self.install_library(values[0])
        else:
            self.uninstall_library(values[0])

    def install_selected_library(self, tree):
        """安装选中的库"""
        selected_items = tree.selection()
        if not selected_items:
            messagebox.showinfo("信息", "请先选择一个库")
            return

        for item in selected_items:
            values = tree.item(item, "values")
            if values and values[1] == "未安装":
                # 调用类方法安装库
                self.install_library(values[0])

    # 独立的 install_library 方法（类层级）
    def install_library(self, lib):
        """安装第三方库"""

        def task():
            self.status_var.set(f"正在安装 {lib}...")
            self.update_progress(0)
            try:
                venv_python = self.get_venv_python()
                if not os.path.exists(venv_python):
                    raise FileNotFoundError("虚拟环境Python未找到")

                # 安装库
                self.log_message(f"安装库: {lib}", "INFO")
                self.update_progress(30)

                result = subprocess.run(
                    [venv_python, "-m", "pip", "install", lib],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace"
                )

                if result.returncode != 0:
                    raise RuntimeError(f"安装失败: {result.stderr}")

                # 更新进度
                self.update_progress(70)

                # 更新已安装包列表
                self.scan_third_party_libs()
                self.log_message(f"{lib} 安装成功", "SUCCESS")
                self.update_progress(100)
                self.status_var.set(f"{lib} 安装完成")

            except Exception as e:
                self.log_message(f"安装 {lib} 失败: {str(e)}", "ERROR")
                self.status_var.set(f"错误: {str(e)}")
            finally:
                self.update_progress(0)

        # 启动线程执行任务
        threading.Thread(target=task, daemon=True).start()

    def uninstall_library(self, lib):
        """卸载第三方库"""

        def task():
            self.status_var.set(f"正在卸载 {lib}...")
            self.update_progress(0)
            try:
                venv_python = self.get_venv_python()
                if not os.path.exists(venv_python):
                    raise FileNotFoundError("虚拟环境Python未找到")

                # 卸载库
                self.log_message(f"卸载库: {lib}", "INFO")
                self.update_progress(30)

                result = subprocess.run(
                    [venv_python, "-m", "pip", "uninstall", lib, "-y"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace"
                )

                if result.returncode != 0:
                    raise RuntimeError(f"卸载失败: {result.stderr}")

                # 更新进度
                self.update_progress(70)

                # 更新已安装包列表
                self.scan_third_party_libs()
                self.log_message(f"{lib} 卸载成功", "SUCCESS")
                self.update_progress(100)
                self.status_var.set(f"{lib} 卸载完成")

            except Exception as e:
                self.log_message(f"卸载 {lib} 失败: {str(e)}", "ERROR")
                self.status_var.set(f"错误: {str(e)}")
            finally:
                self.update_progress(0)

        threading.Thread(target=task, daemon=True).start()

    def check_and_install_deps(self):
        """检查并安装项目依赖"""
        if not self.project_path:
            messagebox.showerror("错误", "请先打开一个Django项目")
            return

        req_file = os.path.join(self.project_path, "requirements.txt")

        # 处理requirements.txt不存在的情况
        if not os.path.exists(req_file):
            choice = messagebox.askyesno(
                "文件缺失",
                "未找到requirements.txt文件\n是否生成新的依赖文件？"
            )
            if choice is None:  # 用户取消
                return

            try:
                venv_python = self.get_venv_python()

                if choice:  # 生成依赖文件
                    result = subprocess.run(
                        [venv_python, "-m", "pip", "freeze"],
                        capture_output=True,
                        text=True,
                        encoding="utf-8"
                    )

                    if result.returncode != 0:
                        raise RuntimeError(f"生成失败: {result.stderr}")

                    with open(req_file, "w", encoding="utf-8") as f:
                        f.write(result.stdout)
                    self.log_message("已从虚拟环境生成requirements.txt", "SUCCESS")
                else:  # 创建空文件
                    with open(req_file, "w", encoding="utf-8") as f:
                        f.write("# 在此输入项目依赖\n")
                    self.log_message("已创建空的requirements.txt", "SUCCESS")

                self.status_var.set("requirements.txt已准备")
                return

            except Exception as e:
                self.log_message(f"处理requirements.txt失败: {str(e)}", "ERROR")
                messagebox.showerror("错误", f"处理requirements.txt失败: {str(e)}")
                return

        # 检查依赖的任务
        def task():
            self.status_var.set("正在检查依赖...")
            self.update_progress(0)
            try:
                # 读取requirements.txt
                self.log_message("读取requirements.txt...", "INFO")
                self.update_progress(10)
                with open(req_file, "r", encoding="utf-8") as f:
                    required_pkgs = [line.strip() for line in f if line.strip() and not line.startswith("#")]

                if not required_pkgs:
                    self.log_message("requirements.txt中未找到依赖", "WARNING")
                    self.status_var.set("无依赖需要安装")
                    return

                # 获取已安装包
                self.log_message("获取已安装包列表...", "INFO")
                self.update_progress(30)
                venv_python = self.get_venv_python()
                result = subprocess.run(
                    [venv_python, "-m", "pip", "list", "--format=freeze"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8"
                )

                if result.returncode != 0:
                    raise RuntimeError(f"获取依赖失败: {result.stderr}")

                installed_pkgs = [line.split("==")[0].lower() for line in result.stdout.splitlines() if "==" in line]

                # 检查缺失依赖
                missing = []
                for pkg in required_pkgs:
                    pkg_name = pkg.split("==")[0].lower()
                    if pkg_name not in installed_pkgs:
                        missing.append(pkg)

                if not missing:
                    self.log_message("所有依赖已安装", "SUCCESS")
                    self.status_var.set("依赖检查完成")
                    return

                # 安装缺失依赖
                self.log_message(f"发现缺失依赖: {', '.join(missing)}", "WARNING")
                self.update_progress(50)

                install_cmd = [venv_python, "-m", "pip", "install"] + missing
                install_result = subprocess.run(
                    install_cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8"
                )

                if install_result.returncode != 0:
                    raise RuntimeError(f"安装失败: {install_result.stderr}")

                self.log_message("缺失依赖安装完成", "SUCCESS")
                self.update_progress(100)
                self.status_var.set("依赖安装完成")

            except Exception as e:
                self.log_message(f"依赖检查失败: {str(e)}", "ERROR")
                self.status_var.set(f"错误: {str(e)}")
                messagebox.showerror("错误", f"依赖检查失败: {str(e)}")
            finally:
                self.update_progress(0)

        threading.Thread(target=task, daemon=True).start()

    def run_project(self):
        """运行Django项目（自动寻找可用端口）"""
        if not self.project_path:
            messagebox.showerror("错误", "请先打开一个Django项目")
            return

        # 检查服务器是否已在运行
        if self.server_process and self.server_process.poll() is None:
            self.log_message("服务器已在运行", "WARNING")
            self.status_var.set("服务器已在运行")
            return

        def task():
            self.status_var.set("正在启动Django项目...")
            self.update_progress(0)
            try:
                venv_python = self.get_venv_python()
                self.log_message(f"使用Python: {venv_python}", "DEBUG")

                # 切换到项目目录
                os.chdir(self.project_path)
                self.log_message(f"切换到项目目录: {self.project_path}", "INFO")
                self.update_progress(20)

                # 自动寻找可用端口
                self.log_message("寻找可用端口...", "INFO")
                self.update_progress(30)

                # 从8000开始尝试，最多尝试20个端口
                base_port = 8000
                max_attempts = 20
                selected_port = None

                for port in range(base_port, base_port + max_attempts):
                    if self.is_port_available(port):
                        selected_port = port
                        self.log_message(f"找到可用端口: {port}", "SUCCESS")
                        break

                if not selected_port:
                    self.log_message(f"在{base_port}-{base_port + max_attempts}范围内未找到可用端口", "ERROR")
                    self.status_var.set("未找到可用端口")
                    return

                # 启动服务器线程
                self.update_progress(50)
                server_thread = threading.Thread(
                    target=self.run_django_server,
                    args=(selected_port,),  # 传递选定的端口
                    daemon=True
                )
                server_thread.start()

                # 等待服务器启动
                self.log_message("等待服务器启动...", "INFO")
                self.update_progress(70)
                time.sleep(2)  # 给服务器启动时间

                # 打开浏览器
                self.update_progress(90)
                url = f"http://127.0.0.1:{selected_port}"
                webbrowser.open(url)
                self.log_message(f"已尝试在浏览器中打开 {url}", "INFO")

                self.update_progress(100)
                self.status_var.set(f"项目运行中 (端口: {selected_port})")

            except Exception as e:
                self.log_message(f"运行项目失败: {str(e)}", "ERROR")
                self.status_var.set(f"错误: {str(e)}")
            finally:
                self.update_progress(0)

        threading.Thread(target=task, daemon=True).start()

    def run_django_server(self, port):
        """使用指定端口运行Django服务器"""
        venv_python = self.get_venv_python()
        try:
            self.server_process = subprocess.Popen(
                [venv_python, "manage.py", "runserver", f"127.0.0.1:{port}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace"
            )

            # 实时输出服务器日志
            while self.server_process.poll() is None:
                for line in self.server_process.stdout:
                    if line:
                        self.log_message(f"服务器: {line.strip()}", "INFO")
                for line in self.server_process.stderr:
                    if line:
                        self.log_message(f"服务器错误: {line.strip()}", "ERROR")

                time.sleep(0.1)

            # 处理剩余输出
            for line in self.server_process.stdout:
                if line:
                    self.log_message(f"服务器: {line.strip()}", "INFO")
            for line in self.server_process.stderr:
                if line:
                    self.log_message(f"服务器错误: {line.strip()}", "ERROR")

        except Exception as e:
            self.log_message(f"服务器进程错误: {str(e)}", "ERROR")
        finally:
            self.server_process = None
            self.log_message("服务器进程已终止", "INFO")

    def is_port_available(self, port):
        """检查端口是否可用"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(('127.0.0.1', port))
            return True
        except socket.error:
            return False
        finally:
            s.close()

    def stop_server(self):
        """停止运行中的服务器"""
        if self.server_process and self.server_process.poll() is None:
            try:
                self.log_message("正在停止服务器...", "INFO")
                self.server_process.terminate()
                self.log_message("服务器终止命令已发送", "INFO")

                # 等待进程结束
                for _ in range(10):
                    if self.server_process.poll() is not None:
                        break
                    time.sleep(0.2)

                if self.server_process.poll() is None:
                    self.log_message("强制终止服务器进程", "WARNING")
                    self.server_process.kill()

                self.server_process = None
                self.log_message("服务器已停止", "SUCCESS")
                self.status_var.set("服务器已停止")

            except Exception as e:
                self.log_message(f"停止服务器失败: {str(e)}", "ERROR")
                self.status_var.set(f"停止服务器错误: {str(e)}")
        else:
            self.log_message("没有运行中的服务器", "INFO")
            self.status_var.set("没有运行中的服务器")

    def generate_file_tree(self):
        """生成项目文件树状图"""
        if not self.project_path:
            messagebox.showerror("错误", "请先打开一个项目")
            return

        # 创建文件树窗口
        file_tree_window = tk.Toplevel(self.root)
        file_tree_window.title("项目文件结构")
        file_tree_window.geometry("800x600")

        # 主框架
        main_frame = ttk.Frame(file_tree_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 树状视图
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # 滚动条
        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 树状组件
        self.file_tree = ttk.Treeview(
            tree_frame,
            columns=("文件路径", "依赖库"),
            yscrollcommand=scrollbar.set,
            selectmode="browse"
        )
        scrollbar.config(command=self.file_tree.yview)

        # 配置列
        self.file_tree.heading("#0", text="文件/目录")
        self.file_tree.heading("文件路径", text="完整路径")
        self.file_tree.heading("依赖库", text="依赖的第三方库")

        self.file_tree.column("#0", width=300, stretch=tk.YES)
        self.file_tree.column("文件路径", width=300, stretch=tk.YES)
        self.file_tree.column("依赖库", width=200, stretch=tk.YES)

        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 添加根节点
        root_node = self.file_tree.insert("", "end", text=os.path.basename(self.project_path),
                                        values=(self.project_path, ""))

        # 构建文件树
        self.build_file_tree(root_node, self.project_path)

        # 展开根节点
        self.file_tree.item(root_node, open=True)

        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)

        close_btn = ttk.Button(
            button_frame,
            text="关闭",
            command=file_tree_window.destroy
        )
        close_btn.pack(side=tk.RIGHT, padx=5)

    def build_file_tree(self, parent_node, path):
        """递归构建文件树"""
        try:
            # 添加目录
            for name in os.listdir(path):
                if name.startswith(".") or name in ["__pycache__", "venv", ".venv", "env"]:
                    continue

                full_path = os.path.join(path, name)
                if os.path.isdir(full_path):
                    # 添加目录节点
                    node = self.file_tree.insert(
                        parent_node, "end",
                        text=name,
                        values=(full_path, ""),
                        tags=("dir",)
                    )
                    # 递归处理子目录
                    self.build_file_tree(node, full_path)
                elif name.endswith(".py"):
                    # 添加Python文件节点
                    libs = self._parse_imports(full_path)
                    libs_str = ", ".join(libs) if libs else "无"
                    self.file_tree.insert(
                        parent_node, "end",
                        text=name,
                        values=(full_path, libs_str),
                        tags=("file",)
                    )

        except Exception as e:
            self.log_message(f"构建文件树失败: {str(e)}", "ERROR")

    def _parse_imports(self, file_path):
        """解析文件中的导入语句"""
        try:
            # 检查文件大小
            if os.path.getsize(file_path) > 2 * 1024 * 1024:  # 2MB
                return ["文件过大跳过解析"]

            with open(file_path, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=file_path)

                imports = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imports.add(alias.name.split(".")[0])
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imports.add(node.module.split(".")[0])

                # 过滤标准库和项目内部模块
                return [
                    lib for lib in imports
                    if lib not in self.stdlib_modules
                    and lib not in self.project_modules
                ]

        except SyntaxError as e:
            self.log_message(f"文件语法错误: {file_path} ({e})", "WARNING")
            return ["语法错误"]
        except Exception as e:
            self.log_message(f"解析文件失败: {file_path} ({e})", "ERROR")
            return ["解析失败"]

    def open_dependency_manager(self):
        """打开依赖管理界面"""
        if not self.project_path:
            messagebox.showerror("错误", "请先打开一个项目")
            return

        # 创建依赖管理窗口
        dep_window = tk.Toplevel(self.root)
        dep_window.title("依赖管理工具")
        dep_window.geometry("800x500")

        # 主框架
        main_frame = ttk.Frame(dep_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 依赖树状视图
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # 滚动条
        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 树状组件
        self.dep_tree = ttk.Treeview(
            tree_frame,
            columns=("库名", "状态", "版本", "引用文件"),
            yscrollcommand=scrollbar.set,
            show="headings",
            selectmode="extended"
        )
        scrollbar.config(command=self.dep_tree.yview)

        # 配置列
        columns = ("库名", "状态", "版本", "引用文件")
        col_widths = [150, 80, 80, 300]
        for col, width in zip(columns, col_widths):
            self.dep_tree.heading(col, text=col)
            self.dep_tree.column(col, width=width, anchor=tk.W)

        self.dep_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 填充数据
        for lib in self.third_party_libs:
            status = "已安装" if lib.lower() in self.installed_packages else "未安装"
            version = self.installed_packages.get(lib.lower(), "-")
            used_files = self.lib_files.get(lib, [])
            used_files_str = "\n".join([os.path.basename(f) for f in used_files[:3]])
            if len(used_files) > 3:
                used_files_str += f"\n...等{len(used_files)}个文件"

            self.dep_tree.insert("", "end", values=(lib, status, version, used_files_str))

        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)

        scan_btn = ttk.Button(
            button_frame,
            text="重新扫描",
            command=self.scan_third_party_libs
        )
        scan_btn.pack(side=tk.LEFT, padx=5)

        install_btn = ttk.Button(
            button_frame,
            text="安装选中",
            command=self.install_selected_dependencies
        )
        install_btn.pack(side=tk.LEFT, padx=5)

        uninstall_btn = ttk.Button(
            button_frame,
            text="卸载选中",
            command=self.uninstall_selected_dependencies
        )
        uninstall_btn.pack(side=tk.LEFT, padx=5)

        close_btn = ttk.Button(
            button_frame,
            text="关闭",
            command=dep_window.destroy
        )
        close_btn.pack(side=tk.RIGHT, padx=5)

    def install_selected_dependencies(self):
        """安装选中的依赖"""
        selected = self.dep_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择要安装的依赖")
            return

        for item in selected:
            values = self.dep_tree.item(item, "values")
            if values and values[1] == "未安装":
                self.install_library(values[0])

    def uninstall_selected_dependencies(self):
        """卸载选中的依赖"""
        selected = self.dep_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择要卸载的依赖")
            return

        for item in selected:
            values = self.dep_tree.item(item, "values")
            if values and values[1] == "已安装":
                self.uninstall_library(values[0])


if __name__ == "__main__":
    # 确保日志目录存在
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)

    try:
        root = tk.Tk()
        app = DjangoProjectManager(root)
        root.mainloop()
    except Exception as e:
        logger.error(f"程序启动失败: {str(e)}", exc_info=True)
        messagebox.showerror("致命错误", f"程序启动失败: {str(e)}\n详细信息请查看日志文件。")
        sys.exit(1)