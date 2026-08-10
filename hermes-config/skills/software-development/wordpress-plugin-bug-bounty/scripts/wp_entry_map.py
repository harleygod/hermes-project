#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WP 插件入口点枚举器 (2026-08-10)
把"扫代码"变成"看结构化地图"——六阶段审计法的阶段①②自动化。

用法:
    python wp_entry_map.py <插件目录> [输出文件]

输出:
    1. PHP 文件清单 + 行数
    2. 入口点: add_action/add_filter 注册 (action名, callback, 文件:行号)
       按类别分组: wp_ajax_nopriv / wp_ajax / admin_post / init / admin_init /
       template_redirect / rest / 其他
    3. 危险函数位置: file_put_contents/fopen/fwrite/unlink/rename/move_uploaded_file/
       readfile/eval/system/exec/shell_exec/unserialize/$wpdb->query/$wpdb->get_var/
       wp_remote_get/wp_remote_post/simplexml_load_string/include/include_once/require
    4. 权限函数位置: current_user_can/check_admin_referer/check_ajax_referer/
       wp_verify_nonce/nonce_field/wp_create_nonce/is_admin
    5. 直接用户输入位置: $_GET/$_POST/$_REQUEST/$_FILES (排除 sanitize 行)

正则近似(不解析 PHP AST), 用于定位; 结论仍需 read_file 读上下文验证。

注意 (Windows/MSYS 坑): 用原生路径 D:/ 或 D:\\ 调用, 不要用 /d/ 格式
(Windows 原生 python 会把 /d/ 解析成 D:\\d\\ 导致找不到文件)。
"""
import os
import re
import sys

HOOK_RE = re.compile(
    r"add_(?:action|filter)\s*\(\s*(['\"])([^'\"]+)\1\s*,\s*([^,)]+?)(?:\s*,\s*[^)]*)?\)",
    re.S,
)
FUNC_RE = re.compile(r"function\s+([a-zA-Z0-9_]+)\s*\(")
DANGEROUS = {
    "file_put_contents": "文件写", "fopen": "文件打开", "fwrite": "文件写",
    "unlink": "文件删除", "rename": "重命名", "move_uploaded_file": "移动上传",
    "readfile": "读文件输出", "eval": "代码执行", "system": "命令执行",
    "exec": "命令执行", "shell_exec": "命令执行", "passthru": "命令执行",
    "unserialize": "反序列化", "simplexml_load_string": "XXE面",
    "wp_remote_get": "SSRF面", "wp_remote_post": "SSRF面",
    "include": "文件包含", "include_once": "文件包含",
    "require": "文件包含", "require_once": "文件包含",
    "wp_handle_upload": "上传(WP标准)", "media_handle_upload": "上传(WP标准)",
    "getimagesize": "图片校验", "wp_check_filetype": "类型校验",
}
DANGEROUS_RE = re.compile(r"\b(" + "|".join(DANGEROUS.keys()) + r")\s*\(")
PERM_RE = re.compile(
    r"\b(current_user_can|check_admin_referer|check_ajax_referer|wp_verify_nonce"
    r"|wp_nonce_field|wp_create_nonce|is_admin|is_user_logged_in|wp_redirect|wp_safe_redirect)\s*\("
)
USERINPUT_RE = re.compile(r"\$_(GET|POST|REQUEST|FILES|COOKIE|SERVER)\b")
SANITIZED_RE = re.compile(r"(sanitize_|absint|intval|esc_|wp_unslash|wp_verify_nonce|isset|empty)")


def scan_php_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        # 跳过 vendor/freemius 等第三方目录
        dirnames[:] = [
            d for d in dirnames
            if d not in ("vendor", "node_modules", "freemius", "lib\\freemius", ".git", "languages")
            and not d.startswith(".")
        ]
        for fn in sorted(filenames):
            if fn.endswith(".php"):
                yield os.path.join(dirpath, fn)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    root = os.path.abspath(sys.argv[1])
    out = sys.argv[2] if len(sys.argv) > 2 else None

    lines_out = []
    hooks = []   # (action, callback, file:line, line_text)
    danger = []  # (func, file:line, line_text)
    perms = []   # (func, file:line, line_text)
    userinput = []  # (file:line, line_text)

    php_files = list(scan_php_files(root))
    lines_out.append(f"# 入口点地图: {root}")
    lines_out.append(f"PHP 文件数: {len(php_files)}\n")

    for f in php_files:
        rel = os.path.relpath(f, root)
        try:
            with open(f, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except Exception as e:
            lines_out.append(f"!! 读取失败 {rel}: {e}")
            continue
        nlines = text.count("\n") + 1
        lines_out.append(f"- {rel} ({nlines} 行)")
        for i, line in enumerate(text.split("\n"), 1):
            for m in HOOK_RE.finditer(line):
                action = m.group(2)
                cb = " ".join(m.group(3).split())
                hooks.append((action, cb, f"{rel}:{i}", line.strip()[:110]))
            for m in DANGEROUS_RE.finditer(line):
                danger.append((m.group(1), DANGEROUS[m.group(1)], f"{rel}:{i}", line.strip()[:110]))
            for m in PERM_RE.finditer(line):
                perms.append((m.group(1), f"{rel}:{i}", line.strip()[:110]))
            if USERINPUT_RE.search(line) and not SANITIZED_RE.search(line):
                userinput.append((f"{rel}:{i}", line.strip()[:110]))

    # ---- 分类输出 ----
    lines_out.append("\n## 入口点分类")
    cats = {
        "wp_ajax_nopriv (未认证AJAX)": [],
        "wp_ajax (登录AJAX)": [],
        "admin_post": [],
        "init/admin_init (任意请求可触发)": [],
        "template_redirect (前端)": [],
        "rest (REST API)": [],
        "shortcode": [],
        "其他钩子": [],
    }
    for action, cb, loc, text in hooks:
        cat = None
        if action.startswith("wp_ajax_nopriv"): cat = "wp_ajax_nopriv (未认证AJAX)"
        elif action.startswith("wp_ajax_"): cat = "wp_ajax (登录AJAX)"
        elif action.startswith("admin_post"): cat = "admin_post"
        elif action in ("init", "admin_init") or action.startswith("init"): cat = "init/admin_init (任意请求可触发)"
        elif action in ("template_redirect", "wp"): cat = "template_redirect (前端)"
        elif action.startswith("rest_"): cat = "rest (REST API)"
        elif action in ("admin_menu", "admin_enqueue_scripts", "wp_enqueue_scripts", "wp_head", "wp_footer", "the_content", "save_post", "admin_footer", "admin_notices", "wp_dashboard_setup", "plugins_loaded", "after_setup_theme", "before_delete_post", "deleted_post", "wp_loaded", "parse_request", "pre_get_posts", "admin_bar_menu", "widgets_init", "wp_ajax_nopriv_*"): cat = "其他钩子"
        else: cat = "其他钩子"
        cats.setdefault(cat, []).append((action, cb, loc, text))

    for cat, items in cats.items():
        if not items:
            continue
        lines_out.append(f"\n### {cat} ({len(items)})")
        for action, cb, loc, text in items:
            lines_out.append(f"  {loc}  [{action}] -> {cb}")

    lines_out.append(f"\n## 危险函数 ({len(danger)})")
    for func, label, loc, text in danger:
        lines_out.append(f"  {loc}  {func} ({label}): {text}")

    lines_out.append(f"\n## 权限/防护函数 ({len(perms)})")
    for func, loc, text in perms:
        lines_out.append(f"  {loc}  {func}: {text}")

    lines_out.append(f"\n## 疑似未过滤用户输入 ({len(userinput)})")
    for loc, text in userinput:
        lines_out.append(f"  {loc}: {text}")

    result = "\n".join(lines_out)
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(result)
        print(f"已写入 {out} ({len(lines_out)} 行)")
    else:
        print(result)


if __name__ == "__main__":
    main()
