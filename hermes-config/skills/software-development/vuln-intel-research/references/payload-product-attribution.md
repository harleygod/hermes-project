# 载荷产品归属：反序列化载荷通常"不认牌子"

## 核心结论
手上一份武器化 Java 反序列化载荷（序列化流 + 恶意 class），用户问"这是哪个产品的洞"时——**载荷本身通常不告诉你**。

CB1/CC 链（PriorityQueue + BeanComparator + cc3 ComparableComparator + TemplatesImpl）+ 写马恶意类
（POJONode CodeSource → webroot → 写 /static/static.jsp AES 内存马），是对
"有 commons-collections 3.x + commons-beanutils (+jackson-databind) 的 Java webapp"的**通用载荷**，
不带任何产品指纹。

- 链本身 = ysoserial 标准 gadget，任何带 cc3+beanutils 的 Java 应用都能承载
- 恶意类 = 通用写马逻辑（CodeSource 反推 webroot、BASE64 解码内嵌 JSP、AES 密钥内存马），不含厂商字符串
- 满足该依赖组合的国产 Java OA/中间件一大把：泛微 e-cology/E-Mobile/e-Bridge、用友 NC、致远、蓝凌、帆软、金蝶……

## 产品归属的唯一依据 = 入口 URL
"这是 XX 产品"的判断，100% 来自入口 URL（/dispatch/invoke/... 之类）。所以：
- URL 忘了/重建过 → 归属只剩零证据，别默认"这是 XX 产品"，先把归属当未证实
- 正确回应：承认载荷不指向任何具体产品，需要 POC 提供者的入口 URL + 目标指纹，或反查工具来源

## 排除法速查（Java 反序列化载荷的场景）
- 目标是 PHP 产品（如泛微 e-office）→ 直接排除，Java 反序列化打不了 PHP
- JDK≤8（sun.misc.BASE64Decoder）→ 老版本线；cc3.x 包名 vs collections4 区分依赖代际
- 硬证据只有两个来源：入口 URL（POC 提供者）+ 源码/jar 里 grep 入口字符串

## 反查工具来源（不依赖提供者、不依赖源码）
恶意类/桩类名能定位生成工具，顺藤摸瓜找作者→目标产品：
- `ysoserial.Pwner<数字>` = 某 ysoserial fork 的 TemplatesImpl 桩命名习惯
- `ysoserial.payloads.util.Gadgets1$Foo` = 原版工具类叫 `Gadgets`，`Gadgets1` 说明是某个 fork/二次封装
- 用 `scripts/payload-static-analysis.py` 提取这些类名（纯静态，不执行反序列化）

## 案例：泛微 dispatch 0day (2026-08)
载荷 = CB1 链 + `ysoserial.Pwner574` 写 /static/static.jsp（AES 密钥 1a1dc91c907325c6）。
静态分析结论：链和恶意类无任何"泛微"指纹；"泛微 dispatch"的归属完全靠那个(忘了的)/dispatch/invoke/ URL。
进一步：泛微 e-cology 9.0 核心 jar（weaver-ecology-3.28）里 grep `/dispatch`、`_SYS_ARGS` 全 0 → 非原生。
正确结论：载荷不指向任何具体产品；要么回问提供者要入口 URL+目标指纹，要么反查 `Pwner574`/`Gadgets1` 对应工具。
