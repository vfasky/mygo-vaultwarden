# 固定官方主密码评分基础

本包是 **评分基础，不是已完成的账号改密/登录策略执行产品**。`Evaluate` 返回官方 zxcvbn 的整数 `Score` 和 `GuessesLog10`；`CheckMinimum` 执行 `score >= minComplexity`（0–4）。空密码无评分且不能满足最低强度。长度、字符要求、账号改密/注册/KDF/登录的具体消费者仍须另行接入，不能以本包测试通过宣称这些流程完成。

## 固定来源与许可证

- Bitwarden clients commit `5983f56ce0cf924eea56c7d8f066f7885825a7ce`：[`password-strength.service.ts`](https://github.com/bitwarden/clients/blob/5983f56ce0cf924eea56c7d8f066f7885825a7ce/libs/common/src/tools/password-strength/password-strength.service.ts) 与 [`package-lock.json`](https://github.com/bitwarden/clients/blob/5983f56ce0cf924eea56c7d8f066f7885825a7ce/package-lock.json)。lock 的 `node_modules/zxcvbn` 是 **4.4.2**，没有改用 zxcvbn-ts 或不相容的 Go 重写。
- npm 原包：<https://registry.npmjs.org/zxcvbn/-/zxcvbn-4.4.2.tgz>。下载后核对固定 lock SHA512：`Bq0B+ixT/DMyG8kgX2xWcI5jUvCwqrMxSFam7m0lAf78nf04hv6lNCsyLYdyYTrCVMqNDY/206K7eExYCeSyUQ==`。
- `../../third_party/zxcvbn/zxcvbn.js` 是原包 `dist/zxcvbn.js`，**821792 bytes**，SHA256 `f42c651f40506acb6b662490f338dd47a5951d3312039c4ab8fe5090484f351a`；完整词典/匹配/评分保持原文件，自动测试固定摘要。保留原 MIT 许可证 `../../third_party/zxcvbn/LICENSE.txt`（Dropbox 2012–2016）。末尾 source-map 注释也未改写；无需 map 即可运行。
- JS 执行引擎 `github.com/dop251/goja` 固定 `v0.0.0-20261007120015-921e62952efd`，MIT，依赖校验记录在根 go.mod/go.sum。不依赖安装 Node 的终端用户环境；Node 只用于独立开发期 oracle。

## 输入、Unicode、阈值与资源边界

按固定官方服务将 `bitwarden`、`bit`、`warden`、调用者 userInputs 与邮箱的第一个 `@` 前的 local-part token 合并，然后按 JS 字符串精确去重。邮箱 local-part 使用 JS `trim().toLowerCase().split(/[^A-Za-z0-9]/)`；域名不加入字典，无 `@` 不提取；空 token 不私自丢弃。密码不 trim、不做 NFC/NFKC、不转换大小写。Go 仅接受合法 UTF-8，传入 goja 后按 JS UTF-16 运算，覆盖 astral emoji 与组合字符，不能用 Go rune 长度替代上游算法。

算法的 `guesses_to_score` 采用原始阈值：`<1005 → 0`、`<1000005 → 1`、`<100000005 → 2`、`<10000000005 → 3`、其余 `4`。`minComplexity` 比较整数评分，不用字符类别或熵公式替代。日期匹配按官方当前年份，生产使用当前时间；测试 oracle 固定 2026 年。

每次调用创建独立解释器，不共享运行时或口令/词典结果，仅缓存编译后的固定公开程序。没有 filesystem/network/console 等宿主绑定，输入作为函数参数传递，绝不拼进脚本。最长口令与邮箱各 1024 UTF-8 bytes、最多 64 个额外词、单词最长 1024 bytes、总输入最多 16384 bytes；超限返回错误，**不截断后评分**。解释器调用栈限制 1024，初始化与计算共 2 秒，并响应调用者取消。固定程序首次编译不含用户输入。这里没有硬内存配额或保证字符串清零的声明；Go/JS GC 管理的秘密副本可能留存。

只返回两个数值；官方含明文 password/token/sequence 的结果被丢弃，异常不含用户输入/JS 栈。任何错误必须在未来消费者中视为无法评估，不能当作满足策略。

## 独立验证

`testdata/generate-vectors.cjs` 在 Node 执行原始官方 npm 包与固定官方输入预处理，生成 `testdata/vectors.json`。28 组 oracle 包含五个评分、字典/leet/键盘/重复/序列/日期、品牌/邮箱/附加用户词、中文、emoji、土耳其大小写、BOM/NBSP trim、组合字符、NUL 和空输入。测试比较整数评分与 guesses_log10（容差 1e-10）；另检查最低评分的全部阈值、空输入/非法值、限长、取消和并发词典隔离。

复现：`node internal/passwordstrength/testdata/generate-vectors.cjs /absolute/path/to/original/zxcvbn.js`。Oracle 固定年份，生产保留当前年份行为。没有运行真实用户口令或读取生产凭据。
