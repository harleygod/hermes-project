<?php
/**
 * WordPress 上传 mime/扩展名校验 —— 实证模拟器
 *
 * 用途：审计 WP 插件上传端点时，判定某个扩展名/文件名能否通过校验。
 * 不要凭记忆推断 get_allowed_mime_types()/wp_check_filetype() 语义，跑真实逻辑。
 *
 * 用法：
 *   1) 下载 WP core 源码（版本按目标站点）：
 *        curl -o wp-functions.php https://raw.githubusercontent.com/WordPress/wordpress-develop/6.5/src/wp-includes/functions.php
 *        # 对比历史行为再拉 5.9：.../wordpress-develop/5.9/src/wp-includes/functions.php
 *   2) php wp-mime-sim.php [wp-functions.php 路径] [额外文件名...]
 *       默认文件：同目录 wp-functions.php
 *       默认测试扩展名：php 系 / html 系 / 双扩展名 / 大小写变体
 *
 * 输出：每个文件名 → wp_check_filetype 返回的 type + 插件式判定 PASS/NO。
 * 依赖 PHP 8+（与多数目标服务器一致）。
 */

$func_file = $argv[1] ?? __DIR__ . '/wp-functions.php';
if (!file_exists($func_file)) {
    fwrite(STDERR, "未找到 $func_file\n先下载: curl -o wp-functions.php https://raw.githubusercontent.com/WordPress/wordpress-develop/6.5/src/wp-includes/functions.php\n");
    exit(1);
}
$src = file_get_contents($func_file);

// --- 提取 wp_get_mime_types() 数组字面量 ---
// 坑：preg_match 需要 /s 修饰符；函数体内 docblock 可能含 'array('；
//     非贪婪 .*? 会在第一个 'return apply_filters(' 处截断 → 用完整 $src 锚定，别用截断的 $body
if (!preg_match('/function wp_get_mime_types\(\)\s*\{.*?return\s*apply_filters\(/s', $src, $m)) {
    fwrite(STDERR, "未匹配到 wp_get_mime_types()\n");
    exit(1);
}
$func_pos = strpos($src, 'function wp_get_mime_types()');
$anchor   = strpos($src, 'apply_filters(', $func_pos) + 14;
$arr_start = strpos($src, 'array(', $anchor);
$arr_lit  = substr($src, $arr_start);
$depth = 0; $end = 0;
for ($i = 0; $i < strlen($arr_lit); $i++) {
    if ($arr_lit[$i] === '(') $depth++;
    elseif ($arr_lit[$i] === ')') { $depth--; if ($depth === 0) { $end = $i + 1; break; } }
}
$t = eval('return ' . substr($arr_lit, 0, $end) . ';');
echo "MIME MAP KEYS: " . count($t) . "\n";
echo "has php: " . (array_key_exists('php', $t) ? 'Y' : 'N') . "\n";
echo "has htm|html: " . (array_key_exists('htm|html', $t) ? 'Y' : 'N') . "\n";

// get_allowed_mime_types() 匿名语义（无 unfiltered_html，WP>=4.7.4 剔除 html/js/swf/exe）
$allowed = $t;
unset($allowed['swf'], $allowed['exe']);
unset($allowed['htm|html'], $allowed['js']);

function wcft($filename, $mimes) {
    foreach ($mimes as $ext_preg => $mime_match) {
        $p = '!\\.(' . $ext_preg . ')$!i';
        if (preg_match($p, $filename, $mm)) return ['ext' => $mm[1], 'type' => $mime_match];
    }
    return ['ext' => false, 'type' => false];
}
// 插件常见判定（ACF Frontend class-upload-file.php:493 样式）：in_array 非严格、对 allowed map 的值
function plugin_fallback_pass($filename, $allowed) {
    $wt = wcft($filename, $allowed);
    return in_array($wt['type'], $allowed);
}

$tests = ['php','phtml','php5','pht','phar','php7','html','htm','shtml','xhtml','js',
          'jpg','png','svg','xml','txt','sh','cgi','pl','py','exe','swf','htaccess',
          'webp','pdf','docx','csv',
          'shell.php.jpg','shell.jpg.php','shell.html.jpg','shell.pHp','shell.pHp5',
          'shell.php.','shell.PHP','.php','shell.php%00.jpg','a.b.php.png'];
$tests = array_merge($tests, array_slice($argv, 2));

echo "--- anonymous (无 unfiltered_html) ---\n";
foreach ($tests as $e) {
    $f  = (strpos($e, '.') !== false && strpos($e, '.') !== 0) ? $e : 'shell.' . $e;
    $wt = wcft($f, $allowed);
    printf("%-18s type=%-30s PASS=%s\n", $f, var_export($wt['type'], true),
           plugin_fallback_pass($f, $allowed) ? 'YES' : 'NO');
}
echo "--- pathinfo ext（插件取扩展名的口径，注意前导点文件名） ---\n";
foreach (['shell.php', '.php', 'shell.php.', 'shell', 'shell..php', 'a..php'] as $f) {
    printf("%-12s pathinfo_ext=%s\n", $f, var_export(pathinfo($f, PATHINFO_EXTENSION), true));
}
