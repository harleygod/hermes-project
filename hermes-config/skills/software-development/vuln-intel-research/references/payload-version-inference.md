# 0day 载荷反推目标版本 (payload-side version inference)

## 触发场景
手上有武器化 0day 载荷(序列化流 value.txt / 恶意 class / exploit 脚本), 无版本信息, 需要反推目标软件版本, 用途: 定向找对应版本源码、定影响范围、判断投入价值。用户要的是"版本结论 + 找源码方向", 不是复述漏洞原理。

## 方法论: 从载荷提取版本约束链
1. **反编译恶意 class**: `javap -p -c` + `javap -verbose`
   - JDK 内部 API → JDK 区间: `sun.misc.BASE64Decoder` → JDK≤8 (JDK9 移除); `java.util.Base64` → JDK8+
   - class 文件 major 版本 (51=Java7, 52=Java8) → 载荷编译目标, 即兼容运行时的下限
   - 反射假设 = 依赖存在性证据: 如 `Class.forName("com.fasterxml.jackson.databind.node.POJONode")` 拿 ProtectionDomain/CodeSource 反推 webroot → 载荷作者在真实环境验证过"目标 WEB-INF/lib 必有 jackson-databind 且被加载"
   - 写马路径逻辑 (找 WEB-INF → {webroot}/static/xxx.jsp) → 部署布局假设: ROOT 部署 + webroot 可写
2. **解析序列化流提取链类名** (scripts/java-serialization-classnames.py):
   - 链类 → 依赖版本线, 关键判别点: 包名 `org.apache.commons.collections` (cc3.x) vs `org.apache.commons.collections4` (cc4.x) — 不同版本线的产品带不同 cc
   - 只需扫描 0x72 (TC_CLASSDESC) + 2 字节长度 + 类名, 去重即可; **不要追求完整解码流**
   - SUID 区分价值低: cc 3.2.1/3.2.2、beanutils 1.8/1.9 的 SUID 基本不变; 完整解析(字段类型码/classAnnotation/superClassDesc 递归)指针易错, 别耗时间
3. **约束映射产品版本历史表**: 按 JDK/依赖/部署布局逐版本线打勾 → 命中/排除/待测三档
4. **公网影响面扫描作组件归属证据**: 混合版本目标全 404 → 该组件不是标准部署暴露组件, 两种自洽假设并列: A) 老版本有但未启用/内网专版; B) 新版本才引入的组件。载荷分不出 A/B 就承认不确定性
5. **输出结构**:
   - 确定的约束链 + 命中/排除/待测
   - 源码检索顺序(按源码可得性 + 版本概率排序) + 用户拿到源码后的验证命令 (grep 组件名定位 servlet 映射, 如 `grep -ri "dispatch" <源码根>` 找 web.xml/spring 路由)
   - 决定性信息缺口: 问源头"验证环境版本号" — 一句话定生死

## 案例: 泛微 dispatch 0day (2026-08)
- 入口 `POST /dispatch/invoke/java.lang.String/copyValueOf`, CB1 链 (PriorityQueue + BeanComparator + cc3 ComparableComparator + TemplatesImpl), 恶意类 `ysoserial.Pwner*` (POJONode CodeSource→webroot, 写 /static/static.jsp AES 内存马加载器)
- 约束: JDK≤8 + cc3.x + beanutils + jackson-databind 2.x (POJONode 反射假设) + ROOT 部署

**泛微 e-cology 版本历史映射** (复用此表做其他泛微载荷):

| 版本线 | 年代 | JDK | lib 特征 | 前端/部署 | 判定 |
|---|---|---|---|---|---|
| 7.x | 2013-2017 | 1.6/1.7 | 无 jackson-databind 2.x | 老 UI | 排除 |
| 8.x | 2018-2021 | 1.8 | cc3.2.x + beanutils + jackson 2.x | resin ROOT, /login/Login.jsp, /js/ecology8.0 | 命中 |
| 9.x | 2021-2022 | 1.8 | 同 8 一脉相承 | ROOT, /wui/index.html, /js/ecology9.0 | 大概率命中 |
| 10 | 2023+ | 1.8 默认 | 依赖可能升级 | 静态部署结构未验证 | 待测 |

- 源码可得性: 8.0 (2020 泄露) > 9.0 (2022 泄露) > 10 (难找) → 检索顺序 8.0 优先
- 公网 ~300 目标 (8/9/10 混合) dispatch 全 404 → 组件非标准暴露, 假设 A/B 并列, 未硬判
- **后续定性 (2026-08-24, 新线索"URL 忘了 + poc 从别人拿的")**: 路径前缀 /dispatch/ 不匹配泛微原生 /api/ /papi/ /weaver/ /dwr/ /workrelate/ 任何一套 + 万能反射桥 URL(/invoke/{类}/{方法}) + 自定义任务协议 body(taskType/taskId/_SYS_ARGS) → 大概率**二开/特定集成模块**, 标准安装包默认不带。含义: 影响面从"所有 e-cology 8/9"缩窄到"装了该集成模块的特定客户"; 标准源码 grep 只能证伪原生、给不了 URL; 真 URL+目标+指纹只在 POC 提供者手里(其 FOFA 搜索词即指纹)。
- **教训**: "实战打过但 URL 忘了"的 POC, 别拿重建 URL 当 ground truth 扫影响面——全 404 只证明"路径不存在", 会误导出"影响面≈0"。先证明入口对(已知-good 目标/源码 servlet 映射)再谈影响面; 无已知-good 目标时枚举 URL 变体分不清"URL 对但目标不对"vs"URL 错"(死锁)。

## Pitfalls
- 别把"载荷在公网全 404"当"漏洞无效" — 可能是组件隐蔽/特定版本/内网专版部署
- 载荷是宽谱的(8/9 都能承载)时, 版本结论给排序 + 决策路径, 不硬给单一答案; 同时给出可一锤定音的信息缺口
- 解析序列化流别追求完整解码, 类名集合就够定位依赖版本线; 魔数校验 `aced0005`
