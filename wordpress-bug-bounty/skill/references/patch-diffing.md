# 补丁分析实战案例：wp-file-upload 5.1.7 → 5.1.8（2026-08-07）

目标：验证"修过 Patchstack 高危洞（CVSS 9.3 SQLi）"的插件是否适合绕过挖掘。
结论：**补丁单点修复（漏修点坐实），但附带 10 字符长度限制杀死利用价值 → 放弃提交**。
方法论价值：补丁分析流程完整跑通，判定标准固化。

## 流程（可复用步骤）
1. changelog 定位修复版本：`plugin_information` API 的 sections.changelog 里搜 "SQL injection" → 上下文显示修复在 **5.1.8**（"fixed SQL injection issue CVSS 9.3 from Patchstack"），修复前版本 = 5.1.7
2. 下载两版 zip：`https://downloads.wordpress.org/plugin/wp-file-upload.5.1.7.zip` 与 `...5.1.8.zip`（socks5h 代理；版本 zip 直接可下）
3. `diff -rq wp-file-upload-5.1.7 wp-file-upload-5.1.8` → 改动只有 3 个文件（lib/wfu_functions.php + 两个文档）→ **典型单点修复信号**
4. `diff` 具体文件：
```diff
< $userdata = $wpdb->get_results('SELECT * FROM '.$table_name2.' WHERE uploadid = \''.$uploadid.'\' AND date_to = 0 ORDER BY propkey');
---
> $userdata = $wpdb->get_results($wpdb->prepare("SELECT * FROM $table_name2 WHERE uploadid = %s AND date_to = 0 ORDER BY propkey", $uploadid));
```
5. grep 同文件同模式找漏修点（5.1.10 仍存在）：
   - **wfu_log_action:3898**（主上传链可达）：`WHERE uploadid = '".$uploadid."' AND property = '".esc_sql($label)."'` —— $uploadid 未转义，与补丁前完全同款
   - :4337/:4396/:4696（$filerec->uploadid，来自 DB）、:4458（wfu_get_oldestrec_from_uniqueid，无调用者=死代码）
6. 追 $uploadid 来源与输入限制（决定可利用性）：
   - wfu_process_files: `$unique_id = $_POST['uniqueuploadid_'.$sid]`（sanitize_text_field，保留引号）→ 客户端可控 ✓
   - 但主上传 callback wfu_ajax_action_callback 强制 `strlen($unique_id) == 10`（5.1.8 加的 "uploadid length check"，changelog 明示）→ payload 空间只剩 `' OR 1=1 #`（恰 10 字符）
7. 注入点分支分析：`if ($existing == null) insert(...)` 无 else → 布尔注入只影响"是否跳过 userdata 写入"，无数据读/写 → 价值不足

## 判定标准（固化）
| 修复形态 | 判定 |
|---|---|
| 单点参数化 + 无输入长度限制 | 漏修点可完整注入 → 挖（UNION/时间盲注空间足） |
| 单点参数化 + 入口加长度限制 | 漏修点存在但只够布尔注入 → 价值低，别交 |
| 统一重写/白名单 | 放弃 |

## 补充教训
- **"修过洞" ≠ 好目标，要再分**：修复质量（参数化 + 长度限制双保险）= 难挖；单点修复 + 无限制 = 绕过目标。这就是 wp_filter_vuln.py 之后还要做补丁分析的原因
- Patchstack 的 9.3 在 5.1.7 能成立是因为当时 **uniqueid 无长度限制**——修复把"洞"和"可利用条件"一起堵了；评估任何"漏修点"时必须先查入口有没有被别的补丁加了硬限制
