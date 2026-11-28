# Server Status

<img src="assets/favicon.svg" width="100px">

用 Fiber、SQLite 和 Vue 监控单台服务器。访客可以查看过去 24 小时的 CPU、内存、网络上下行、各站点请求量，以及按请求次数绘制的访客国家/地区矩形树图。管理员还可以查看每 5 秒更新的实时指标、具体访客 IP，并管理参与统计的日志文件。界面提供简体中文、英文和深浅主题。

> [!NOTE]
> 本项目由 Vibe Coding 完成

## 启动

需要 Go 1.26 或以上版本和 Bun。从项目根目录运行，首次克隆时一并拉取前端子模块。

```sh
git submodule update --init
(cd frontend && bun install --frozen-lockfile && bun run build)
go run .
```

打开 [本机监控页](http://localhost:3000)。Fiber 会提供构建好的前端和 API。首次部署时先由管理员访问 `/register` 创建唯一账户，再将服务公开。注册成功后会自动登录，弹出日志选择窗口。勾选至少一个文件并保存；之后可以在首页的设置中调整。

开发时在一个终端执行 `go run .`，另一个终端执行以下命令。Vite 会把 `/api` 转发到本机 3000 端口，后端地址可通过 `VITE_API_TARGET` 修改。

```sh
cd frontend
bun install --frozen-lockfile
bun run dev
```

## Docker 部署

在项目根目录构建镜像。首次克隆请先拉取前端子模块。

在 Linux 服务器上运行以下命令。容器使用宿主机网络以采集服务器接口的上下行速率，服务监听本机 3000 端口，适合由同机 Caddy 反向代理。可按需要调整 `LISTEN_ADDR`。[Docker 主机网络说明](https://docs.docker.com/engine/network/drivers/host/)

```sh
docker run -d --name server-status 
--restart unless-stopped 
--network host 
-e LISTEN_ADDR=127.0.0.1:7890 
-v <$HOST/db>:/app/caddy_log:ro 
-v <$HOST/caddy_log>:/app/db 
zhouc1230/server-status
```

根据服务器上的实际位置替换 `$HOST/db` 和 `$HOST/caddy_log`。SQLite 会在挂载的数据库目录中读写 `database.db`，挂载已有目录即可沿用账户和历史数据。日志目录末尾的 `:ro` 表示容器只读，宿主机上的 Caddy 仍可写入日志。确保运行用户能写入数据库目录、读取日志。

使用桥接网络时，将 `--network host` 和 `LISTEN_ADDR` 两项替换为 `-p 127.0.0.1:3000:3000`，带宽统计将反映容器网络接口。

## 日志与访问统计

将 Caddy 的 JSON Lines 访问日志写入 `./caddy_log/`，每条记录以换行结束。站点名取文件名去掉 `.json` 后的部分。一个文件对应一个折线图筛选项，例如 `blog.example.com.json` 对应 `blog.example.com`。每个站点可在 Caddyfile 中配置如下日志块，输出路径替换成实际的绝对路径。

> [!IMPORTANT]
> 注意配置日志的时候，mode权限为0644（默认为600）

```caddyfile
example.com {
    # ...

    log {
        output file <$HOST/caddy_log>/example.com.json {
            mode 0644
            roll_size 100mb
            roll_interval 24h
            roll_keep 0
        }
        format json
    }
}

```

后端需要对选中的普通 JSON 文件有读取权限。保存选择后立即扫描，之后每 5 分钟处理新增记录。服务以日志中的 `ts` 统计最近 24 小时的 HTTP 请求，每个五分钟时段分别汇总站点访问次数和每个 IP 的请求次数。失败响应、重定向和静态资源请求均计入访问量。更改来源后，已经入库的数据保留至到期。日志跨越多个站点时，可将它们分文件输出以分别查看。

客户端地址优先使用 Caddy 记录的 `request.client_ip`，缺失或无效时使用 `request.remote_ip`。Caddy 在 CDN 或反向代理后面时，应在 Caddy 配置中指定可信代理和正确的客户端 IP 请求头，否则统计可能显示代理节点的位置。

日志偏移与统计计数在同一个数据库事务中更新。重启可以从已提交的位置继续，在线轮换时会先读完已打开的旧文件。停机期间若日志已移入归档，重启只会读取配置的当前文件。历史记录的保留和清理以五分钟时段为单位。

## 离线 IP 属地

服务内置 2026 年 11 月版 DB-IP IP to Country Lite，IPv4 和 IPv6 查询都在本机完成。前端按所选语言显示国家/地区名称，私网地址单独归类，无法定位的地址显示为“未知”。如需更新，下载新版 Country MMDB 并解压，再设置 `GEOIP_DB_PATH` 指向该文件并重启。新读入的请求会使用新版数据。[DB-IP 官方下载页](https://db-ip.com/db/download/ip-to-country-lite)

IP Geolocation by [DB-IP](https://db-ip.com/)。随项目分发的数据库采用 [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/) 许可。

## 性能与存储

CPU 和内存以百分比显示。网络速率根据主机接口累计收发字节之差计算，单位是 B/s。每 5 秒采样，按五分钟时段取平均值写入 SQLite。新安装的系统会在首个有样本的时段结束后显示性能历史。

默认数据库是 `./db/database.db`。其中保存唯一账户的 bcrypt 哈希、令牌签名密钥、refresh token 摘要、日志配置及偏移、性能样本和访问统计。服务定期删除超出 24 小时的样本和访问统计。access token 的有效期为 15 分钟，refresh token 的有效期为 7 天，每次刷新会轮换，退出登录会撤销该 refresh token。

| 环境变量 | 默认值 | 用途 |
| --- | --- | --- |
| `LISTEN_ADDR` | `:3000` | Fiber 监听地址 |
| `DATA_DIR` | `./db` | SQLite 数据目录 |
| `CADDY_LOG_DIR` | `./caddy_log` | Caddy 访问日志目录 |
| `JWT_SECRET` | 首次自动生成并持久化 | 可选的自管签名密钥，至少 32 字节 |
| `GEOIP_DB_PATH` | 内置国家/地区数据库 | 可选的本地 Country MMDB 路径 |

## 验证

```sh
go test ./...
(cd frontend && bun run build)
```
