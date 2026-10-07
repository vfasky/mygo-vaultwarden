# 附件实现进度与固定协议来源

**当前附件客户端候选已接入 Session 与原生列表/上传/下载/删除，等待独立 Review。** 最新接口、验证与平台边界见 [并行附件交接](parallel/attachments.md)。以下固定来源和 binary/transport 说明记录 `14bbaf0` 基础阶段；其中“下一步/本轮未接入”的描述是该阶段历史，不代表当前候选仍只有底层。整客户端其他功能由并行卡及最终集成验收。

## 固定来源

- SDK commit `39dbb510f5eae82f5cbfd527b0f70a01d5626ec1`：[attachment.rs](https://github.com/bitwarden/sdk-internal/blob/39dbb510f5eae82f5cbfd527b0f70a01d5626ec1/crates/bitwarden-vault/src/cipher/attachment.rs)，`AttachmentFile::decrypt`、`AttachmentFileView::encrypt_composite`、`AttachmentView::encrypt_composite`。文件名用 cipher key 加密；有 attachment key 时用 cipher key 包装该 key，文件内容用 attachment key 加密。新附件的 `size` 是 **密文**字节数。
- 同文件 `test_attachment_without_key` 提供本地测试使用的独立官方二进制向量。**无 attachment key 的 legacy v1 文件实际读取使用 user/org key**（不是把用户 key 分享给组织，也不能假设仅修改 organizationId 就能迁移）。独立 item-key 项目若还含这种旧附件，其文件读取仍须保留此分支。现有独立 item-key 共享本轮未更改；旧附件完整迁移仍未实现。
- SDK [symmetric.rs](https://github.com/bitwarden/sdk-internal/blob/39dbb510f5eae82f5cbfd527b0f70a01d5626ec1/crates/bitwarden-crypto/src/enc_string/symmetric.rs) 的 `EncString::from_buffer/to_buffer`：type 2 为 `0x02 || IV(16) || HMAC-SHA256(32) || AES-256-CBC-PKCS#7 ciphertext`。MAC 输入是 `IV || ciphertext`，key 前32字节用于AES，后32字节用于HMAC。当前只支持认证 type2，旧无MAC type0/新COSE格式仍显式拒绝，不能宣称所有历史二进制格式已支持。
- Vaultwarden commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`、版本1.37.4：[ciphers.rs](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/ciphers.rs)，`post_attachment_v2`（1167行）、`UploadData`（1211行）、`post_attachment_v2_data`（1393行）。`POST /api/ciphers/{id}/attachment/v2`接收`key/fileName/fileSize/adminRequest`；返回attachmentId、url、fileUploadType=0、cipherResponse或cipherMiniResponse；direct URL是`/ciphers/{id}/attachment/{attachmentId}`（API相对路径）。上传`POST /api/ciphers/{id}/attachment/{attachmentId}`使用multipart字段`data`，v2已保存key无需重复发送。
- `get_attachment`（1127行）返回下载元数据；URL可能为签名root附件地址或外部存储。`post_attachment_share`（1442行）先删除旧附件再创建，不能把它当原子迁移或失败可盲重试接口。legacy无key迁移必须建立可核对的分阶段流程；本轮没有调用这些服务器写接口。

## 内部接口与边界

`attachment_crypto.go`：

- `attachmentEncryptedSize(size)`：明文0–512MiB（含端点）；密文 `49 + (floor(size/16)+1)*16`，空文件65字节，最大536870977字节。有限的磁盘/内存资源策略，不是无限大文件支持。
- `encryptAttachment(ctx, io.Reader, plaintextSize, key)`：精确读取所声明大小，拒绝短/长输入，64KiB分块CBC/HMAC，随机IV，输出rewound密文`*attachmentSpool`。
- `decryptAttachment(ctx, io.Reader, ciphertextSize, key)`：先完整认证密文到私有磁盘spool，再解密到另一私有spool；MAC/填充/大小/取消错误不返回明文。工作内存64KiB，磁盘峰值约密文+明文两份；不是将文件读进JSON或整文件内存。
- `attachmentSpool`是包内对象，`.file/.size`只供后续Session代码使用，`.close()`关闭并删除其临时文件，`.rewind()`归零。os.CreateTemp按0600创建到系统临时目录（测试使用本会话TMPDIR），所有错误路径defer清理。删除属于普通文件删除，不承诺磁盘安全擦除；极端文件系统删除失败目前不向外暴露路径或错误。产品发布仍须采用安全目录/不覆盖原子发布，并在发布前重新验证授权；这个基础没有实现发布。
- ctx在读写块和返回前检查；阻塞Reader本身必须支持取消。HTTP请求已绑定ctx和5分钟超时；任意外部Reader不能因这个包装自动获得可中断IO。buffer清零，不承诺Go运行时或磁盘的全量安全擦除。

`attachment_transport.go`：

- `(*Client).downloadAttachment(ctx, signedURL, ciphertextSize, key)`：独立HTTP客户端仅复用transport；不继承cookie jar、Bearer、device/header/referer、redirect规则。所有重定向拒绝；HTTPS外部URL可用，HTTP仅已配置的同loopback origin。拒绝userinfo/fragment/相对URL/非法query/decoded点路径/反斜线/NUL。保留签名query原始编码，错误不含URL、响应或token。固定`Accept-Encoding: identity`，拒绝内容编码/Content-Length不符，用最多size+1字节检测chunked超长，再交crypto处理。
- `(*Client).uploadAttachment(ctx, cipherID, attachmentID, token, encryptedSpool)`：**只支持Vaultwarden direct v2上传**。从已验证ID构造当前vault base path下的API地址，不接受服务器提供的任意URL；Bearer只发此origin。multipart字段`data`，固定公开文件名`attachment.bin`；只有小envelope在内存，文件从spool流出，显式Content-Length。没有goroutine/pipe泄漏风险。拒绝重定向；响应读取至64KiB+1后拒绝超限，错误响应不透传。外部预签名上传/Azure fileUploadType=1未实现，不得把Bearer direct上传函数用于外部URL。
- 底层不刷新token、不重试、不补偿删除、不解释状态成功。Session下一步必须实现refresh先checkpoint、guard、MutationUncertainError和已知attachmentID核对；401/非200并不表示元数据或文件没有部分成功。

## 本轮证据与未验证项

- 官方SDK固定legacy binary向量解密；原有EncString格式互通；空文件、AES边界、64KiB边界、8MiB+3及碎片Reader往返。
- 每个向量字节逐一篡改、所有截断位置、额外尾字节、声明大小错误/溢出、错误key、正确MAC但坏PKCS#7、取消和临时文件0600/移除。
- HTTPS**跨origin**预签名下载无凭据/cookie/device header；签名query保持；恶意URL、错误Content-Length/chunked超长/encoding/状态/MAC、302不跟随。
- 8MiB multipart流传输、base path与form字段、非法ID零请求；307不跟随；401/500/超限响应/连接中断只一次POST，无自动重试或DELETE。HTTP下载在body途中取消，返回ErrCancelled且不交付明文spool。
- 本轮`go test ./...`、`go vet ./...`、`go build`、`go test -race ./...`通过。没有新增公开API/桥ABI/Swift代码，不将历史Swift、系统AutoFill或Keychain验证算本轮通过。没有真实服务回环、安装、窗口或签名验证；未启动Docker/用户应用。

下一步直接实现受控Session的v2两阶段与原生入口，再验证个人和组织真实回环，接legacy完整跨key迁移及Send。原完整卡片其他账号/MFA/组织/桥范围仍保持。
