# 首次使用开始计时的代理令牌

这个 fork 默认保护所有代理数据入口，包括 GitHub、Hugging Face、Docker Registry、镜像搜索及离线镜像包。静态登录页面、健康检查和不返回镜像数据的 `/v2/` 协议探测可以匿名访问。管理登录会话不能替代下载令牌。

## 本地启动与部署配置

设置环境变量 `AUTH_ADMIN_PASSWORD`（12–72 字节）。管理员使用此密码登录 `/admin`，无需注册账号。不要使用服务器 SSH 密码，也不要将真实密码提交到仓库。

Docker Compose 从本地 `.env` 读取此变量，并使用持久卷 `hubproxy-auth` 保存令牌状态：

```sh
docker compose up -d --build
```

默认要求 HTTPS 登录 Cookie；在 Caddy/Nginx 后保留 `cookieSecure = true`。仅在本机 HTTP 开发测试时设置 `AUTH_COOKIE_SECURE=false`。原有容器与反向代理不会因本地修改自动更新。

| 配置 | 默认值 | 用途 |
| --- | --- | --- |
| `[auth].enabled` / `AUTH_ENABLED` | `true` | 保护代理；只有显式 `false` 才关闭 |
| `[auth].dataFile` / `AUTH_DATA_FILE` | `data/tokens.json` | 持久状态，单进程独占使用 |
| `[auth].cookieSecure` / `AUTH_COOKIE_SECURE` | `true` | HTTPS 管理会话 |
| `AUTH_ADMIN_PASSWORD` | 必须设置 | 管理密码，通过环境提供 |

未设置有效密码、无法保存令牌文件或文件损坏时启动失败，不降级成公开代理。一个数据文件只支持一个进程；不支持多副本共享文件。

## 使用规则

1. 登录，创建令牌时选择有效时长。默认 60 分钟，支持 1 分钟至 30 天。
2. 创建时只返回一次完整令牌（256 位随机数，小写十六进制），服务端只保存其 SHA-256 摘要。
3. 创建、复制网址、管理列表刷新、搜索镜像与查看镜像信息不会开始计时。
4. 首次通过令牌校验的代理下载请求启动计时：包括 Docker HEAD 探测、文件 GET、Git smart-HTTP 请求以及离线包准备请求。上游失败也不会撤回或延长计时。
5. 有效期内支持并发、分层请求、重试和范围下载，后续请求不会续期。
6. 到期拒绝新的请求；已获准的传输继续完成。过期后的新分层请求或断点续传需要新令牌。因此要给大镜像预留足够时间。
7. 首次激活原子保存到磁盘，重启不重置计时。删除令牌会立即禁止后续请求。

完整令牌只在创建响应中显示。当前浏览器标签页用 sessionStorage 保存选中的令牌；重新登录后可创建新令牌或在管理页面填入已保存的令牌。

```sh
# 将 TOKEN 替换为创建时返回的令牌
curl -L 'https://gitfast.boyweb.net/TOKEN/https://github.com/owner/repo/releases/download/tag/file.zip'
docker pull gitfast.boyweb.net/TOKEN/library/nginx:latest
docker pull gitfast.boyweb.net/TOKEN/ghcr.io/owner/image:tag
```

Docker 的实际请求 `/v2/TOKEN/...` 在鉴权后移除 TOKEN，再进入原有镜像代理处理器。无需 `docker login`。此方案使用显式镜像名，不能将带路径的地址直接当成透明 `registry-mirrors` 配置。

原有离线镜像包的两分钟一次性下载票据仍然保留；它与本功能的代理令牌是两种独立校验，生成的下载地址同时携带两者。

## 凭证与缓存

登录会话保存在服务端内存中，12 小时失效；重启要求重新登录，但下载令牌的时间不受影响。写管理接口需要同源请求及自定义请求头。登录尝试有速率限制。

令牌网址本身就是凭证。应用日志只记录方法和状态，不记录路径。部署时也应关闭或脱敏外层反向代理/CDN 的 URL 日志，并禁止对代理入口进行强制缓存。程序对受保护响应设置 `private, no-store`，不向上游传递管理 Cookie、Authorization 或 Referer；上游响应不能设置本站 Cookie，且在浏览器中使用 sandbox CSP 隔离。

## 验证

```sh
npm --prefix web ci
npm --prefix web run build
cd src
go test -race ./...
go vet ./...
```

测试覆盖首次激活、并发激活、固定到期、重启保持状态、写入失败时拒绝请求、登录/退出/CSRF、删除失效、无令牌的各入口、过期时已有传输，以及本地 Registry 的完整镜像清单/配置/分层读取和文件重定向/Range 转发。
