# Easy Pass

一个无服务器的网页版密码管理器：

- 前端静态托管在 GitHub Pages。
- Dropbox OAuth Code + PKCE 连接用户自己的 Dropbox。
- 密码库只保存为 Dropbox App Folder 根目录下的 `/vault.enc`。
- `vault.enc` 使用 Argon2id 派生 AES-256-GCM 密钥后加密。
- 支持自定义普通/敏感字段、TOTP 一次性密码和历史密码查看。
- 主密码和自定义字段共用随机密码生成器，长度支持 5-48 位。
- 主密码可在解锁后的设置中修改，最小长度为 10 位。

## 本地运行

```bash
npm install
npm run dev
```

打开 Vite 输出的本地地址。应用内置 Dropbox App key：`56efgyouoypazep`，也可以在设置里覆盖。

## Dropbox App 配置

在 Dropbox App Console 创建应用：

- API: Scoped access
- Access: App folder
- Permissions: `files.content.read`, `files.content.write`, `files.metadata.read`
- OAuth 2 Redirect URIs:
  - 本地开发地址，例如 `http://localhost:5173/`
  - GitHub Pages 地址，例如 `https://<user>.github.io/easy-pass/`

这个应用是纯前端公共客户端，不需要也不能放 Dropbox App secret。

## GitHub Pages 部署

仓库已包含 `.github/workflows/deploy.yml`。在 GitHub 仓库设置里：

1. Pages Source 选择 GitHub Actions。
2. 可选：添加仓库变量 `VITE_DROPBOX_APP_KEY`，用于覆盖内置 App key。
3. 推送到 `main` 后 workflow 会构建并部署 `dist/`。

如果没有设置 `VITE_DROPBOX_APP_KEY`，会使用内置 App key。用户仍可在页面设置里手动输入其他 App key，值只保存在当前浏览器。

隐私协议页面会随 Pages 一起发布：`https://<user>.github.io/easy-pass/privacy.html`。

## 安全边界

- 主密码不会写入 localStorage 或 Dropbox；解锁后派生出的 `CryptoKey` 只保留在当前页面内存中。
- Dropbox 只保存加密后的 `vault.enc`，Dropbox OAuth token 保存在当前浏览器 localStorage。
- 自定义“普通/敏感”字段只是界面显示模式不同；两者在 `vault.enc` 中都会被加密。
- TOTP secret 和历史密码同样只保存在加密 vault 内。
- 多设备同步使用 Dropbox 文件 `rev` 做乐观并发；远端变更时不会静默覆盖。
- 没有密码找回。主密码丢失时，`vault.enc` 无法解密。
