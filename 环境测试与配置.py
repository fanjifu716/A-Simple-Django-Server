import os
import sys
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
import subprocess
import platform
import winreg
import logging
from datetime import datetime
import ctypes
import threading
import shutil
import argparse
import traceback
import tempfile

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def refresh_environment():
    """广播环境变量更改"""
    HWND_BROADCAST = 0xFFFF
    WM_SETTINGCHANGE = 0x001A
    SMTO_ABORTIFHUNG = 0x0002
    logger = logging.getLogger("ToolFinder")
    try:
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment", SMTO_ABORTIFHUNG, 2000, None
        )
        logger.info("环境变量刷新广播已发送")
    except Exception as e:
        logger.warning(f"环境变量刷新失败: {str(e)}")

def show_error(title, message):
    """显示错误消息，优先使用 ctypes（不依赖 Tkinter），否则打印到控制台"""
    try:
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x10)  # MB_ICONERROR
    except:
        print(f"{title}: {message}")

def check_environment():
    """启动前检查环境，返回 (is_valid, error_message)"""
    logger = logging.getLogger("ToolFinder")
    logger.info("开始环境检测")

    # 检查 Python 版本
    required_version = (3, 6)  # 最低支持 Python 3.6
    current_version = sys.version_info[:2]
    if current_version < required_version:
        error = f"Python 版本过低，需要 Python {required_version[0]}.{required_version[1]} 或更高，当前版本：{current_version[0]}.{current_version[1]}"
        logger.error(error)
        return False, error

    # 检查 Tkinter
    try:
        import tkinter
        tkinter.Tk().destroy()  # 测试 Tkinter 初始化
        logger.info("Tkinter 检测通过")
    except Exception as e:
        error = f"Tkinter 不可用，请确保 Python 环境正确安装了 Tcl/Tk：{str(e)}"
        logger.error(error)
        return False, error

    # 检查日志目录写权限
    log_dir = "logs"
    try:
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        test_file = os.path.join(log_dir, "test_write.txt")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        logger.info(f"日志目录 {log_dir} 写权限检测通过")
    except Exception as e:
        error = f"无法写入日志目录 {log_dir}，请确保有写权限或更改目录：{str(e)}"
        logger.error(error)
        return False, error

    # 检查管理员权限（Windows）
    if platform.system() == "Windows" and not is_admin():
        logger.warning("非管理员权限运行，部分功能可能受限")
        # 不强制退出，仅记录警告

    # 检查脚本路径编码
    try:
        script_path = os.path.abspath(sys.argv[0])
        script_path.encode('ascii')  # 测试是否为纯 ASCII
        logger.info("脚本路径编码检测通过")
    except UnicodeEncodeError:
        error = f"脚本路径 {sys.argv[0]} 包含非 ASCII 字符，可能导致问题，建议重命名为英文路径"
        logger.warning(error)
        # 不强制退出，仅记录警告

    logger.info("环境检测全部通过")
    return True, ""

class ToolFinderApp:
    def __init__(self, root):
        self.root = root
        self.logger = logging.getLogger("ToolFinder")
        try:
            self.logger.info("初始化 ToolFinderApp")
            self.root.title("开发工具查找器")
            self.root.geometry("800x600")
            self.root.resizable(True, True)

            # 字体适配
            self.system = platform.system()
            self.default_font = ("SimHei", 11) if self.system == "Windows" else ("WenQuanYi Zen Hei", 11)
            self.root.option_add("*Font", self.default_font)

            # 存储工具路径
            self.python_envs = []
            self.pycharm_paths = []
            self.installed_packages = {}

            self.create_widgets()
            self.logger.info("程序初始化完成")
        except Exception as e:
            self.logger.error(f"初始化失败: {str(e)}\n{traceback.format_exc()}")
            show_error("初始化错误", f"程序启动失败: {str(e)}")
            raise

    def setup_logging(self):
        log_dir = "logs"
        try:
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
        except Exception as e:
            show_error("日志错误", f"无法创建日志目录: {str(e)}")
            sys.exit(1)
        log_file = os.path.join(log_dir, f"tool_finder_{datetime.now().strftime('%Y%m%d_%H-%M%S')}.log")
        logger = logging.getLogger("ToolFinder")
        logger.setLevel(logging.DEBUG)
        try:
            file_handler = logging.FileHandler(log_file, encoding="utf-8", errors="ignore")
            file_handler.setLevel(logging.DEBUG)
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s:%(funcName)s:%(lineno)d - %(message)s")
            file_handler.setFormatter(formatter)
            console_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            logger.addHandler(console_handler)
            logger.info("日志系统初始化完成")
        except Exception as e:
            show_error("日志错误", f"日志初始化失败: {str(e)}")
            sys.exit(1)

    def create_widgets(self):
        self.logger.info("创建界面控件")
        try:
            # 主框架
            main_frame = ttk.Frame(self.root, padding="10")
            main_frame.pack(fill=tk.BOTH, expand=True)

            # 工具栏
            toolbar = ttk.Frame(main_frame)
            toolbar.pack(fill=tk.X, pady=(0, 5))
            self.search_btn = ttk.Button(toolbar, text="搜索", command=self.start_search_thread)
            self.search_btn.pack(side=tk.LEFT, padx=5)
            self.add_tooltip(self.search_btn, "搜索 Python 和 PyCharm 路径")
            self.show_packages_btn = ttk.Button(toolbar, text="查看包", command=self.show_installed_packages, state=tk.DISABLED)
            self.show_packages_btn.pack(side=tk.LEFT, padx=5)
            self.add_tooltip(self.show_packages_btn, "显示所有 Python 环境的已安装第三方库")
            self.test_env_btn = ttk.Button(toolbar, text="测试", command=self.test_environment)
            self.test_env_btn.pack(side=tk.LEFT, padx=5)
            self.add_tooltip(self.test_env_btn, "测试 Python 和 pip 命令是否生效")
            ttk.Button(toolbar, text="日志", command=self.show_logs).pack(side=tk.LEFT, padx=5)
            self.add_tooltip(toolbar.winfo_children()[-1], "查看运行日志")
            self.status_var = tk.StringVar(value="准备就绪")
            ttk.Label(toolbar, textvariable=self.status_var, foreground="blue").pack(side=tk.LEFT, padx=10)

            # 选项卡
            self.notebook = ttk.Notebook(main_frame)
            self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            self.python_frame = ttk.Frame(self.notebook)
            self.pycharm_frame = ttk.Frame(self.notebook)
            self.packages_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.python_frame, text="Python 环境")
            self.notebook.add(self.pycharm_frame, text="PyCharm 路径")
            self.notebook.add(self.packages_frame, text="已安装包")
        except Exception as e:
            self.logger.error(f"创建控件失败: {str(e)}\n{traceback.format_exc()}")
            raise

    def add_tooltip(self, widget, text):
        """为控件添加工具提示"""
        def show_tooltip(event):
            tooltip = tk.Toplevel(widget)
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root + 10}+{event.y_root + 10}")
            ttk.Label(tooltip, text=text, background="white", relief="solid", borderwidth=1).pack(padx=5, pady=2)
            widget.tooltip = tooltip
        def hide_tooltip(event):
            if hasattr(widget, 'tooltip'):
                widget.tooltip.destroy()
        widget.bind("<Enter>", show_tooltip)
        widget.bind("<Leave>", hide_tooltip)

    def start_search_thread(self):
        self.logger.info("启动搜索线程")
        self.search_btn.config(state=tk.DISABLED)
        threading.Thread(target=self.search_tools, daemon=True).start()

    def search_tools(self):
        self.logger.info("开始搜索工具")
        self.status_var.set("正在搜索工具...")
        self.root.after(0, self.root.update)
        self.clear_frames()
        self.python_envs.clear()
        self.pycharm_paths.clear()
        self.installed_packages.clear()
        try:
            self.find_all_python_with_pip()
            self.find_all_pycharm_paths()
            if self.python_envs:
                self.status_var.set("正在检测已安装的第三方库...")
                self.root.after(0, self.root.update)
                self.detect_installed_libraries()
                self.root.after(0, lambda: self.show_packages_btn.config(state=tk.NORMAL))
            self.root.after(0, self.show_python_envs)
            self.root.after(0, self.show_pycharm_paths)
            self.root.after(0, lambda: self.status_var.set("搜索完成"))
            self.logger.info(f"搜索完成 - 找到 {len(self.python_envs)} 个 Python 环境，{len(self.pycharm_paths)} 个 PyCharm 路径")
        except Exception as e:
            self.root.after(0, lambda: self.status_var.set(f"搜索出错: {str(e)}"))
            self.logger.error(f"搜索过程中发生错误: {str(e)}\n{traceback.format_exc()}")
        finally:
            self.root.after(0, lambda: self.search_btn.config(state=tk.NORMAL))

    def clear_frames(self):
        self.logger.debug("清空界面框架")
        for frame in [self.python_frame, self.pycharm_frame, self.packages_frame]:
            for widget in frame.winfo_children():
                widget.destroy()

    def find_all_python_with_pip(self):
        self.logger.info("开始搜索 Python 环境")
        path_dirs = os.environ.get("PATH", "").split(os.pathsep)
        for exe in ["python", "python3"]:
            python_exe = shutil.which(exe)
            if python_exe and self._is_valid_python(python_exe):
                self.logger.info(f"在 PATH 中找到 Python: {python_exe}")
                self._check_python_env(python_exe)
        if self.system == "Windows":
            common_dirs = [
                r"C:\Python",
                r"C:\Program Files\Python",
                r"C:\Program Files (x86)\Python",
                fr"C:\Users\{os.getlogin()}\AppData\Local\Programs\Python"
            ]
            for dir_path in common_dirs:
                if os.path.exists(dir_path):
                    self.logger.debug(f"扫描目录: {dir_path}")
                    for root, _, files in os.walk(dir_path):
                        if "venv\\scripts" in root.lower() or "venv\\bin" in root.lower():
                            continue
                        for file in files:
                            if file.lower() == "python.exe" and self._is_valid_python(os.path.join(root, file)):
                                python_exe = os.path.join(root, file)
                                self.logger.info(f"在常见目录中找到 Python: {python_exe}")
                                self._check_python_env(python_exe)
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Python\PythonCore") as root_key:
                    index = 0
                    while True:
                        try:
                            version_key = winreg.EnumKey(root_key, index)
                            with winreg.OpenKey(root_key, version_key + r"\InstallPath") as install_key:
                                install_dir, _ = winreg.QueryValueEx(install_key, "")
                                python_exe = os.path.join(install_dir, "python.exe")
                                if os.path.exists(python_exe) and self._is_valid_python(python_exe):
                                    self.logger.info(f"从注册表找到 Python: {python_exe} (版本: {version_key})")
                                    self._check_python_env(python_exe)
                            index += 1
                        except OSError:
                            break
            except FileNotFoundError:
                self.logger.debug("注册表路径不存在: SOFTWARE\Python\PythonCore")
        else:
            common_paths = ["/usr/bin", "/usr/local/bin", os.path.expanduser("~/.pyenv/versions")]
            for path in common_paths:
                python_exe = shutil.which("python3", path=path)
                if python_exe and self._is_valid_python(python_exe):
                    self.logger.info(f"在非 Windows 路径中找到 Python: {python_exe}")
                    self._check_python_env(python_exe)

    def _is_valid_python(self, python_exe):
        self.logger.debug(f"验证 Python 路径: {python_exe}")
        if "lib\\venv" in python_exe.lower() or "lib/venv" in python_exe.lower() or "pythonw.exe" in python_exe.lower():
            self.logger.debug(f"排除无效 Python 路径: {python_exe}")
            return False
        try:
            result = subprocess.check_output([python_exe, "--version"], stderr=subprocess.STDOUT, text=True, timeout=5)
            self.logger.debug(f"验证有效 Python: {python_exe}, 版本: {result.strip()}")
            return True
        except Exception as e:
            self.logger.warning(f"验证 Python 路径失败: {python_exe}, 错误: {str(e)}")
            return False

    def _check_python_env(self, python_exe):
        self.logger.debug(f"检查 Python 环境: {python_exe}")
        for env in self.python_envs:
            if env[0] == python_exe:
                self.logger.debug(f"Python 环境已存在，跳过: {python_exe}")
                return
        try:
            version_output = subprocess.check_output([python_exe, "--version"], stderr=subprocess.STDOUT, text=True, timeout=5).strip()
        except Exception as e:
            version_output = "版本未知"
            self.logger.warning(f"无法获取 Python 版本: {python_exe}, 错误: {str(e)}")
        pip_exe = None
        python_install_dir = None
        try:
            python_install_dir = subprocess.check_output([python_exe, "-c", "import sys; print(sys.base_prefix)"], text=True, timeout=5).strip()
            self.logger.debug(f"从 sys.base_prefix 获取安装目录: {python_install_dir}")
        except Exception as e:
            self.logger.warning(f"无法通过 sys.base_prefix 获取安装目录: {python_exe}, 错误: {str(e)}")
            python_install_dir = os.path.dirname(python_exe)
            self.logger.debug(f"使用后备安装目录: {python_install_dir}")
        if not python_install_dir or not os.path.exists(python_install_dir):
            self.logger.error(f"无效的 Python 安装目录: {python_install_dir}")
            return
        self.logger.debug(f"验证安装目录存在: {python_install_dir}")
        scripts_dir = os.path.join(python_install_dir, "Scripts" if self.system == "Windows" else "bin")
        pip_path = os.path.join(scripts_dir, "pip.exe" if self.system == "Windows" else "pip")
        if os.path.exists(pip_path):
            pip_exe = pip_path
            self.logger.debug(f"找到 pip 路径: {pip_exe}")
        else:
            try:
                result = subprocess.check_output([python_exe, "-m", "pip", "--version"], stderr=subprocess.STDOUT, text=True, timeout=5)
                for line in result.splitlines():
                    if "pip" in line.lower() and "from" in line.lower():
                        pip_dir = line.split("from")[1].strip().split()[0]
                        pip_exe = os.path.join(os.path.dirname(pip_dir), "pip.exe" if self.system == "Windows" else "pip")
                        if os.path.exists(pip_exe):
                            self.logger.debug(f"通过 pip --version 找到 pip 路径: {pip_exe}")
                            break
            except Exception as e:
                self.logger.warning(f"无法找到 pip 路径: {python_exe}, 错误: {str(e)}")
        self.python_envs.append((python_exe, version_output, pip_exe, python_install_dir))
        self.logger.info(f"添加 Python 环境: {python_exe}, 版本: {version_output}, pip: {pip_exe}, 安装目录: {python_install_dir}")

    def find_all_pycharm_paths(self):
        self.logger.info("开始搜索 PyCharm 路径")
        if self.system == "Windows":
            reg_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\pycharm64.exe",
                r"SOFTWARE\JetBrains\Installations"
            ]
            for reg_path in reg_paths:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                        if "JetBrains\Installations" in reg_path:
                            index = 0
                            while True:
                                try:
                                    sub_key = winreg.EnumKey(key, index)
                                    with winreg.OpenKey(key, sub_key) as sub_key_handle:
                                        path, _ = winreg.QueryValueEx(sub_key_handle, "Path")
                                        if "pycharm" in path.lower() and path not in self.pycharm_paths:
                                            self.pycharm_paths.append(path)
                                            self.logger.info(f"从注册表找到 PyCharm 路径: {path}")
                                    index += 1
                                except OSError:
                                    break
                        else:
                            pycharm_path, _ = winreg.QueryValueEx(key, "")
                            if os.path.exists(pycharm_path) and pycharm_path not in self.pycharm_paths:
                                self.pycharm_paths.append(pycharm_path)
                                self.logger.info(f"从注册表找到 PyCharm 路径: {pycharm_path}")
                except FileNotFoundError:
                    self.logger.debug(f"注册表路径不存在: {reg_path}")
            common_dirs = [
                r"C:\Program Files\JetBrains",
                fr"C:\Users\{os.getlogin()}\AppData\Local\JetBrains\Toolbox\apps\PyCharm"
            ]
            for dir_path in common_dirs:
                if os.path.exists(dir_path):
                    self.logger.debug(f"扫描 PyCharm 目录: {dir_path}")
                    for root, _, files in os.walk(dir_path):
                        for file in files:
                            if file.lower() in ["pycharm64.exe", "pycharm.exe"]:
                                pycharm_exe = os.path.join(root, file)
                                if pycharm_exe not in self.pycharm_paths:
                                    self.pycharm_paths.append(pycharm_exe)
                                    self.logger.info(f"从文件系统找到 PyCharm 路径: {pycharm_exe}")
        else:
            common_paths = [
                "/usr/bin/pycharm",
                "/usr/local/bin/pycharm",
                os.path.expanduser("~/Applications/PyCharm CE.app/Contents/MacOS/pycharm"),
            ]
            for path in common_paths:
                if os.path.exists(path) and path not in self.pycharm_paths:
                    self.pycharm_paths.append(path)
                    self.logger.info(f"从非 Windows 路径找到 PyCharm: {path}")

    def show_python_envs(self):
        self.logger.debug("显示 Python 环境")
        if not self.python_envs:
            ttk.Label(self.python_frame, text="未找到有效 Python 环境", foreground="red").pack(anchor="w", padx=10, pady=5)
            return
        ttk.Label(self.python_frame, text="Python 环境列表", font=("SimHei", 12, "bold")).pack(anchor="w", padx=10, pady=5)
        canvas = tk.Canvas(self.python_frame)
        scrollbar = ttk.Scrollbar(self.python_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas_frame = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        for i, (python_exe, version, pip_exe, install_dir) in enumerate(self.python_envs):
            frame = ttk.Frame(scrollable_frame)
            frame.pack(fill=tk.X, padx=5, pady=2)
            ttk.Label(frame, text=f"路径: {python_exe}\n版本: {version}\n目录: {install_dir}", anchor="w", width=60).pack(side=tk.LEFT)
            if pip_exe and os.path.exists(pip_exe):
                ttk.Label(frame, text=f"pip: {pip_exe}", foreground="green", width=30).pack(side=tk.LEFT, padx=5)
                ttk.Button(frame, text="添加 pip", command=lambda p=pip_exe: self.copy_and_add_to_path(p, add_type="pip")).pack(side=tk.LEFT, padx=5)
                self.add_tooltip(frame.winfo_children()[-1], "将 pip 路径添加到环境变量")
                ttk.Button(frame, text="查看包", command=lambda p=python_exe, v=version: self.show_packages_for_library(p, v)).pack(side=tk.LEFT, padx=5)
                self.add_tooltip(frame.winfo_children()[-1], "查看此 Python 环境的第三方库")
            else:
                ttk.Label(frame, text="pip: 未找到", foreground="red", width=30).pack(side=tk.LEFT, padx=5)
                ttk.Button(frame, text="添加 pip", state=tk.DISABLED).pack(side=tk.LEFT, padx=5)
            ttk.Button(frame, text="添加 Python", command=lambda p=python_exe, i=install_dir: self.copy_and_add_to_path(p, add_type="python", install_dir=i)).pack(side=tk.LEFT, padx=5)
            self.add_tooltip(frame.winfo_children()[-1], "将 Python 路径添加到环境变量")

    def show_pycharm_paths(self):
        self.logger.debug("显示 PyCharm 路径")
        if not self.pycharm_paths:
            ttk.Label(self.pycharm_frame, text="未找到 PyCharm 路径", foreground="red").pack(anchor="w", padx=10, pady=5)
            return
        ttk.Label(self.pycharm_frame, text="PyCharm 路径列表", font=("SimHei", 12, "bold")).pack(anchor="w", padx=10, pady=5)
        canvas = tk.Canvas(self.pycharm_frame)
        scrollbar = ttk.Scrollbar(self.pycharm_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        for path in self.pycharm_paths:
            frame = ttk.Frame(scrollable_frame)
            frame.pack(fill=tk.X, padx=5, pady=2)
            ttk.Label(frame, text=f"路径: {path}", anchor="w", width=80).pack(side=tk.LEFT)
            ttk.Button(frame, text="复制", command=lambda p=path: self.copy_path(p)).pack(side=tk.LEFT, padx=5)
            self.add_tooltip(frame.winfo_children()[-1], "复制 PyCharm 路径到剪贴板")

    def copy_path(self, path):
        self.logger.info(f"复制路径: {path}")
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(path)
            messagebox.showinfo("成功", f"已复制路径：\n{path}")
            self.logger.info(f"用户复制了路径：{path}")
        except Exception as e:
            self.logger.error(f"复制路径失败: {str(e)}")
            messagebox.showerror("错误", f"复制路径失败: {str(e)}")

    def copy_and_add_to_path(self, path, add_type="pip", install_dir=None):
        self.logger.info(f"调用 copy_and_add_to_path: path={path}, add_type={add_type}, install_dir={install_dir}")
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(path)
            self.logger.info(f"用户复制了路径：{path}")
            paths_to_add = []
            path_type = add_type.capitalize()
            if add_type == "python":
                if not install_dir or not os.path.exists(install_dir):
                    messagebox.showerror("错误", f"无效的 Python 安装目录: {install_dir}")
                    self.logger.error(f"无效的 Python 安装目录: {install_dir}")
                    return
                paths_to_add = [install_dir]
                self.logger.debug(f"准备添加 Python 路径: {install_dir}")
            elif add_type == "pip":
                pip_dir = os.path.dirname(path)
                if not pip_dir or not os.path.exists(pip_dir):
                    messagebox.showerror("错误", f"无效的 pip 目录: {pip_dir}")
                    self.logger.error(f"无效的 pip 目录: {pip_dir}")
                    return
                paths_to_add = [pip_dir]
                self.logger.debug(f"准备添加 pip 路径: {pip_dir}")
            else:
                messagebox.showerror("错误", "无效的添加类型")
                self.logger.error(f"无效的添加类型: {add_type}")
                return
            if self.system == "Windows":
                user_updated = False
                system_updated = False
                messages = []
                # 规范化路径
                for i, p in enumerate(paths_to_add):
                    paths_to_add[i] = os.path.normpath(p)
                    self.logger.debug(f"规范化路径: {p} -> {paths_to_add[i]}")
                # 用户 PATH
                try:
                    user_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_ALL_ACCESS)
                    try:
                        user_old_path, _ = winreg.QueryValueEx(user_key, "Path")
                    except FileNotFoundError:
                        user_old_path = ""
                    self.logger.debug(f"用户 PATH 原始值: {user_old_path}")
                    user_old_paths = [os.path.normpath(p).lower() for p in user_old_path.split(os.pathsep) if p]
                    for path_to_add in paths_to_add:
                        normalized_path = os.path.normpath(path_to_add).lower()
                        if normalized_path not in user_old_paths:
                            user_new_path = user_old_path + (os.pathsep if user_old_path else "") + path_to_add
                            winreg.SetValueEx(user_key, "Path", 0, winreg.REG_EXPAND_SZ, user_new_path)
                            user_updated = True
                            messages.append(f"已将路径 {path_to_add} 添加到用户环境变量 PATH")
                            self.logger.info(f"成功添加 {path_to_add} 到用户 PATH")
                        else:
                            messages.append(f"路径 {path_to_add} 已存在于用户 PATH，跳过")
                            self.logger.debug(f"用户 PATH 已包含 {path_to_add}，跳过")
                        # 验证写入
                        user_key_verify = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ)
                        user_new_path_verify, reg_type = winreg.QueryValueEx(user_key_verify, "Path")
                        winreg.CloseKey(user_key_verify)
                        if reg_type != winreg.REG_EXPAND_SZ:
                            messages.append(f"警告：用户 PATH 键类型错误，应为 REG_EXPAND_SZ，实际为 {reg_type}")
                            self.logger.warning(f"用户 PATH 键类型错误: {reg_type}")
                        if path_to_add.lower() not in user_new_path_verify.lower():
                            messages.append(f"警告：用户 PATH 添加 {path_to_add} 后未在注册表中找到")
                            self.logger.warning(f"用户 PATH 添加 {path_to_add} 验证失败")
                    winreg.CloseKey(user_key)
                except Exception as e:
                    messages.append(f"添加路径到用户环境变量失败: {str(e)}")
                    self.logger.error(f"添加路径到用户 PATH 失败: {str(e)}\n{traceback.format_exc()}")
                # 系统 PATH
                try:
                    system_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", 0, winreg.KEY_ALL_ACCESS)
                    try:
                        system_old_path, _ = winreg.QueryValueEx(system_key, "Path")
                    except FileNotFoundError:
                        system_old_path = ""
                    self.logger.debug(f"系统 PATH 原始值: {system_old_path}")
                    system_old_paths = [os.path.normpath(p).lower() for p in system_old_path.split(os.pathsep) if p]
                    for path_to_add in paths_to_add:
                        normalized_path = os.path.normpath(path_to_add).lower()
                        if normalized_path not in system_old_paths:
                            system_new_path = system_old_path + (os.pathsep if system_old_path else "") + path_to_add
                            winreg.SetValueEx(system_key, "Path", 0, winreg.REG_EXPAND_SZ, system_new_path)
                            system_updated = True
                            messages.append(f"已将路径 {path_to_add} 添加到系统环境变量 PATH")
                            self.logger.info(f"成功添加 {path_to_add} 到系统 PATH")
                        else:
                            messages.append(f"路径 {path_to_add} 已存在于系统 PATH，跳过")
                            self.logger.debug(f"系统 PATH 已包含 {path_to_add}，跳过")
                        # 验证写入
                        system_key_verify = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", 0, winreg.KEY_READ)
                        system_new_path_verify, reg_type = winreg.QueryValueEx(system_key_verify, "Path")
                        winreg.CloseKey(system_key_verify)
                        if reg_type != winreg.REG_EXPAND_SZ:
                            messages.append(f"警告：系统 PATH 键类型错误，应为 REG_EXPAND_SZ，实际为 {reg_type}")
                            self.logger.warning(f"系统 PATH 键类型错误: {reg_type}")
                        if path_to_add.lower() not in system_new_path_verify.lower():
                            messages.append(f"警告：系统 PATH 添加 {path_to_add} 后未在注册表中找到")
                            self.logger.warning(f"系统 PATH 添加 {path_to_add} 验证失败")
                    winreg.CloseKey(system_key)
                except Exception as e:
                    messages.append(f"添加路径到系统环境变量失败: {str(e)}")
                    self.logger.error(f"添加路径到系统 PATH 失败: {str(e)}\n{traceback.format_exc()}")
                # 广播环境变量更改并显示结果
                if user_updated or system_updated:
                    refresh_environment()
                    message = "\n".join(messages) + "\n\n注意：环境变量更改可能需要注销或重启系统以完全生效。\n是否打开新 CMD 窗口测试？"
                    if messagebox.askyesno("操作结果", message):
                        cmd_command = (
                            f"echo 测试 {path_type} 路径: {paths_to_add[0]} & "
                            f"reg query HKCU\\Environment /v Path & "
                            f"reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment /v Path & "
                            f"where {path_type.lower()}.exe & "
                            f"{path_type.lower()} --version & "
                            f"echo PATH: %PATH% & "
                            f"pause"
                        )
                        subprocess.Popen(["cmd.exe", "/k", cmd_command])
                        self.logger.info(f"打开 CMD 测试 {path_type} 路径: {paths_to_add[0]}")
                else:
                    messagebox.showinfo("提示", "\n".join(messages))
            else:
                messagebox.showinfo("提示", "非 Windows 系统暂不支持添加到环境变量功能")
        except Exception as e:
            self.logger.error(f"添加路径到环境变量失败: {str(e)}\n{traceback.format_exc()}")
            messagebox.showerror("错误", f"添加路径到环境变量时出错: {str(e)}")

    def show_logs(self):
        self.logger.info("显示日志")
        log_dir = "logs"
        try:
            if not os.path.exists(log_dir) or not os.listdir(log_dir):
                messagebox.showinfo("日志", "未找到日志文件")
                self.logger.info("未找到日志文件")
                return
            log_files = sorted([os.path.join(log_dir, f) for f in os.listdir(log_dir)], key=os.path.getmtime, reverse=True)
            with open(log_files[0], "r", encoding="utf-8", errors="ignore") as f:
                log_content = f.read()
            log_window = tk.Toplevel(self.root)
            log_window.title(f"日志文件: {os.path.basename(log_files[0])}")
            log_window.geometry("800x600")
            text_widget = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, font=("Consolas", 9))
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            text_widget.insert(tk.END, log_content)
            text_widget.config(state=tk.DISABLED)
            self.logger.info(f"用户查看日志: {log_files[0]}")
        except Exception as e:
            messagebox.showerror("错误", f"无法打开日志文件: {str(e)}")
            self.logger.error(f"无法打开日志文件: {str(e)}\n{traceback.format_exc()}")

    def detect_installed_libraries(self):
        self.logger.info("检测已安装的第三方库")
        self.installed_packages.clear()
        for python_exe, version, pip_exe, _ in self.python_envs:
            try:
                result = subprocess.check_output([python_exe, "-m", "pip", "list", "--format=freeze"], stderr=subprocess.STDOUT, text=True, timeout=60)
                packages = {line.split("==")[0]: line.split("==")[1] for line in result.splitlines() if "==" in line}
                self.installed_packages[python_exe] = packages
                self.logger.info(f"成功检测到 {python_exe} 的已安装包，数量: {len(packages)}")
            except Exception as e:
                self.installed_packages[python_exe] = {}
                self.logger.error(f"无法获取 {python_exe} 的已安装包列表: {str(e)}\n{traceback.format_exc()}")

    def show_installed_packages(self):
        self.logger.info("显示已安装的第三方库")
        self.clear_frames()
        if not self.python_envs:
            messagebox.showinfo("提示", "未找到 Python 环境，无法显示已安装包")
            self.logger.info("未找到 Python 环境")
            return
        ttk.Label(self.packages_frame, text="已安装的第三方库", font=("SimHei", 12, "bold")).pack(anchor="w", padx=10, pady=5)
        canvas = tk.Canvas(self.packages_frame)
        scrollbar = ttk.Scrollbar(self.packages_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        for python_exe, version, _, _ in self.python_envs:
            frame = ttk.Frame(scrollable_frame)
            frame.pack(fill=tk.X, padx=5, pady=5)
            ttk.Label(frame, text=f"Python 环境: {python_exe} ({version})", font=("SimHei", 10, "bold")).pack(anchor="w")
            packages = self.installed_packages.get(python_exe, {})
            if packages:
                text_widget = scrolledtext.ScrolledText(frame, wrap=tk.WORD, font=("Consolas", 9), height=5)
                text_widget.pack(fill=tk.X, padx=10, pady=2)
                sorted_packages = sorted(packages.items(), key=lambda x: x[0].lower())
                display_text = "包名".ljust(30) + "版本\n" + "-" * 60 + "\n"
                for name, ver in sorted_packages:
                    display_text += f"{name.ljust(30)} {ver}\n"
                text_widget.insert(tk.END, display_text)
                text_widget.config(state=tk.DISABLED)
            else:
                ttk.Label(frame, text="未找到已安装的包或获取失败", foreground="red").pack(anchor="w", padx=10)

    def show_packages_for_library(self, python_exe, version):
        self.logger.info(f"显示 {python_exe} 的第三方库")
        packages = self.installed_packages.get(python_exe, {})
        if not packages:
            messagebox.showinfo("提示", f"{version} 无已安装包或获取失败")
            self.logger.info(f"{version} 无已安装包")
            return
        window = tk.Toplevel(self.root)
        window.title(f"{version} - 已安装第三方库")
        window.geometry("600x400")
        text_widget = scrolledtext.ScrolledText(window, wrap=tk.WORD, font=("Consolas", 9))
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        sorted_packages = sorted(packages.items(), key=lambda x: x[0].lower())
        display_text = "包名".ljust(30) + "版本\n" + "-" * 60 + "\n"
        for name, ver in sorted_packages:
            display_text += f"{name.ljust(30)} {ver}\n"
        text_widget.insert(tk.END, display_text)
        text_widget.config(state=tk.DISABLED)

    def test_environment(self):
        self.logger.info("执行环境测试")
        try:
            cmd_command = (
                "echo Current PATH: %PATH% & "
                "reg query HKCU\\Environment /v Path & "
                "reg query HKLM\\SYSTEM\CurrentControlSet\Control\Session Manager\Environment /v Path & "
                "where python.exe & "
                "python --version & "
                "where pip.exe & "
                "pip --version & "
                "pause"
            )
            subprocess.Popen(["cmd.exe", "/k", cmd_command])
            self.logger.info("已打开 CMD 测试环境")
        except Exception as e:
            messagebox.showerror("错误", f"测试环境失败: {str(e)}")
            self.logger.error(f"测试环境失败: {str(e)}\n{traceback.format_exc()}")

def init_logging(debug=False):
    """初始化日志系统，优先尝试当前目录，失败则使用临时目录"""
    logger = logging.getLogger("ToolFinder")
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(name)s - %(message)s")
    
    # 控制台输出
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 文件输出
    log_dir = "logs"
    log_file = None
    try:
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        log_file = os.path.join(log_dir, f"tool_finder_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        file_handler = logging.FileHandler(log_file, encoding="utf-8", errors="ignore")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.info(f"日志系统初始化完成，日志文件：{log_file}")
    except Exception as e:
        logger.warning(f"无法创建日志文件 {log_file}：{str(e)}")
        # 回退到临时目录
        try:
            temp_dir = tempfile.gettempdir()
            log_file = os.path.join(temp_dir, f"tool_finder_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
            file_handler = logging.FileHandler(log_file, encoding="utf-8", errors="ignore")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            logger.info(f"日志系统回退到临时目录：{log_file}")
        except Exception as e2:
            logger.error(f"无法初始化日志文件：{str(e2)}")

def main():
    parser = argparse.ArgumentParser(description="ToolFinder 开发工具查找器")
    parser.add_argument("--debug", action="store_true", help="启用调试模式，显示详细控制台输出")
    args = parser.parse_args()

    # 初始化日志
    init_logging(args.debug)

    # 环境检测
    is_valid, error_message = check_environment()
    if not is_valid:
        show_error("环境错误", f"{error_message}\n请修复环境后重试。")
        logging.getLogger("ToolFinder").error(f"环境检测失败：{error_message}")
        input("按任意键退出...")
        sys.exit(1)

    try:
        # 移除管理员权限检查，改在环境检测中警告
        root = tk.Tk()
        app = ToolFinderApp(root)
        app.setup_logging()  # 确保实例日志
        root.mainloop()
    except Exception as e:
        logging.getLogger("ToolFinder").error(f"主程序失败: {str(e)}\n{traceback.format_exc()}")
        show_error("致命错误", f"程序启动失败: {str(e)}")
        if args.debug:
            print(traceback.format_exc())
        input("按任意键退出...")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"程序运行出错: {str(e)}")
        input("按任意键退出...")
        sys.exit(1)