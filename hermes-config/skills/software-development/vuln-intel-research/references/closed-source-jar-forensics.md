# 闭源/半开源 Java 组件的漏洞考古（jar 反编译确认调用链）

## 触发场景
目标组件的新版闭源：GitHub 主仓库只有 example/文档、Maven sources jar 是空壳（只有 README），
但二进制 jar 有 class。需要确认：接口路径、请求参数名、漏洞调用链（危险方法）。

实例：JimuReport 2.3.4（jeecgboot/jimureport 主仓库只有 example；starter 走 Maven 发布，sources 空壳）。

## 步骤
1. **Maven Central 版本列表**（拿准确版本号）：
   `curl -s "https://repo1.maven.org/maven2/<group路径>/<artifact>/" | grep -oP 'href="[^"]*[0-9][^"]*/"' | tr -d 'href="/'`
   group 点号换斜杠，如 org.jeecgframework.jimureport → org/jeecgframework/jimureport
2. **下载二进制 jar 用阿里云镜像直连**（repo1.maven.org 走 Clash 代理龟速会超时，阿里云秒下）：
   `curl -s --noproxy "*" --max-time 120 -o xxx.jar "https://maven.aliyun.com/repository/central/<同上路径>/<artifact>-<ver>.jar"`
3. `unzip -o -q xxx.jar -d cls && find cls -name "*.class" | wc -l`
4. **定位类**：
   - `grep -rla "<方法名>|<路径串>" cls --include="*.class"` —— 在 class 二进制里搜字符串定位类（最快）
   - `find cls -name "*.class" | grep -iE "FreeMarker|Controller"`
5. **看方法签名**：`javap -p cls/.../X.class`（注意混淆名：DesignReportController → b/a.class）
6. **反编译字节码找危险调用**：`javap -c -p cls/.../X.class | grep -E "AviatorEvaluator|Runtime|defineClass|invokestatic"` ——
   实例：FreemarkerMethod.compute() 第 166 条 `invokestatic AviatorEvaluator.execute(String,Map)` = 漏洞实锤
7. **常量池字符串找接口路径/共享变量**：`javap -v cls/.../X.class | grep -E "String +#[0-9]+" | sed 's/.*String +//' | sort -u`
   实例：`/jmreport/queryFieldBySql`、`/jmreport/save`、共享变量名 `jeecg`（FreeMarkerUtils 渲染入口
   `Map.put("jeecg", new FreemarkerMethod())`）
8. **参数名**：`javap -l -p`（编译带 debug info 时 LocalVariableTable 有参数名）
9. 老版本源码兜底：老版组件常有完整开源源码（如 JeecgBoot v3.5.0 时代 jmreport 是内置模块），
   sparse checkout 只拉目标模块：
   `git clone --depth 1 --branch <tag> --filter=blob:none --sparse <url> && git sparse-checkout set "<模块>"`

## Pitfalls
- **sources jar 可能空壳**：5440 字节、只有 README.md → 别浪费轮次，直接二进制 jar
- **curl -o /tmp/xxx 在 git-bash/MSYS 不可靠**（Windows 原生 curl 的路径转换问题，文件不落盘）→ 用当前目录
- **javap 输出被 grep 当二进制**（报 "Binary file matches"）→ grep 加 `-a`
- 大 jar 下载：repo1.maven.org 走代理超时 → 阿里云镜像 `--noproxy "*"` 直连
- 模糊名混淆：controller/service 常混淆成 a/b/m.class，看 `Compiled from "XxxController.java"` 确认身份
- FreeMarker 模板里 Java 方法调用需要参数个数匹配签名：`compute(List,Object,String)` 三参，
  表达式是第三参；正则提取括号内容的逻辑决定 payload 写法——写 POC 前必须确认调用形态，别猜
