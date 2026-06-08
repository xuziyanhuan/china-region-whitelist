# 省/市白名单一键脚本

这个项目用于按中国地区 IP 段限制 VPS 入站访问：只有交互选择的省份或城市可以访问指定端口，其他来源访问这些端口会被拒绝。每个端口都有独立白名单；对同一个端口再次应用会追加新的地区，不会覆盖旧地区；对新端口应用不会影响已有端口。脚本同时托管 `INPUT` 和 `FORWARD` 链，因此机器上的转发端口也可以受到同一套按端口隔离的白名单限制。

## 文件结构

- `install.sh`：用户交互入口，处理数字菜单、省市和端口选择、SSH 客户端 IP 确认、root/依赖检查、快捷命令安装和卸载
- `tools/firewall_lib.sh`：Bash 集成层，定位本地数据、包装 Python 工具、检测/安装 `iptables` 和 `ipset`、检测 SSH 客户端 IP、执行渲染命令
- `tools/region_tool.py`：运行时数据解析和命令渲染工具，解析省市选择器、验证 CIDR/端口/客户端 IP、去重 CIDR 范围、生成 ipset 和 iptables 命令
- `tools/prepare_data.py`：离线数据准备脚本，解析 `data/cncity.md`、下载 CIDR 文件到 `data/regions/`、生成 `data/regions.json`
- `data/regions.json`：省市索引，每个条目指向 `data/regions/` 下的 CIDR 文本文件
- `data/regions/*.txt`：本地 CIDR 段文件
- `data/cncity.md`：省市区划元数据
- `vendor/ipipfree.ipdb`：本地 ipdb 参考文件（可选）
- `tests/test_firewall_lib.py`：Python 命令渲染器和 Bash 集成的单元测试

## 安装

### 方式一：从 GitHub 一键部署（需要外网）

```bash
curl -L https://github.com/xuziyanhuan/china-region-whitelist/archive/refs/heads/main.tar.gz | tar xz && \
cd china-region-whitelist-main && \
sudo bash install.sh install-shortcut && \
cd ..
```

### 方式二：本地部署（无需外网）

将整个项目目录上传到服务器后，在项目目录内运行：

```bash
sudo bash install.sh install-shortcut
```

安装完成后，直接输入 `U` 或 `u` 打开交互菜单。

## 使用

### 交互菜单

安装快捷命令后，直接输入 `U` 或 `u` 打开交互菜单：

```bash
U
```

菜单选项：

1. **按省市选择白名单地区**：选择省份和城市，然后指定端口，应用到防火墙
2. **仅手动输入 IP 白名单**：跳过省市选择，直接输入 IP/CIDR，然后指定端口
3. **添加 Docker 网桥白名单**：将 Docker 网桥接口（`docker0`、`br-*`）添加到白名单，容器流量不受端口限制影响
4. **清除本脚本创建的规则和 ipset**：清除防火墙规则子菜单
   - **0**：返回上级菜单
   - **1**：仅清除 Docker 网桥白名单
   - **2**：仅清除 lo（本地回环）白名单
   - **ALL**：清除全部端口规则、lo 和 Docker 白名单
   - **输入端口号**：清除指定端口的白名单规则（多个端口用空格/逗号分隔）
5. **查看当前白名单规则**：显示所有托管端口、ipset 和 iptables 规则详情
6. **更新本地 CIDR 数据**：从 GitHub 重新下载省市 CIDR 数据（需要外网）
7. **清除规则并删除脚本本体**：卸载所有规则、快捷命令和项目目录（需输入 `DELETE` 确认）
8. **检查脚本更新**：检查并更新脚本到最新版本（需要外网）
0. **退出**

### 命令行用法

也可以直接使用命令行方式：

**应用规则**（交互式选择省市和端口）：

```bash
sudo bash install.sh apply
```

脚本会列出所有省份，例如 `1.北京市`、`19.广东省`。选择省份后继续列出该省全部城市，例如 `1.广州市`、`3.深圳市`。你可以输入编号，也可以直接输入名称；多个选择用空格、英文逗号、中文逗号或顿号分隔。

如果不想选择省/市，可以在省份选择时输入 `0`，然后手动输入白名单 IP 或 CIDR，例如 `1.2.3.4 192.168.1.0/24`。选择了省/市后，也可以继续额外添加手动 IP。

地区或手动 IP 选择完成后需要输入要限制的端口，例如 `22 80 443`。**对同一端口再次应用会追加新地区，不会覆盖旧规则**。如果想从零开始配置，先运行 `clear` 清除对应端口规则。

**查看状态**：

```bash
sudo bash install.sh status
```

**清除规则**（交互式选择要清除的端口或全部清除）：

```bash
sudo bash install.sh clear
```

**预览生成的命令**（不实际应用）：

```bash
bash install.sh dry-run
```

**卸载**（清除规则、快捷命令和项目目录）：

```bash
sudo bash install.sh uninstall
```

该命令会要求输入 `DELETE` 确认，然后清除所有端口规则、lo 白名单、Docker 白名单，删除 `/usr/local/bin/U` 和 `/usr/local/bin/u`，并删除当前项目目录。

## 安全提示

`apply` 会拒绝所有未命中白名单来源对**你选定端口**的 TCP/UDP 访问。如果把 SSH 端口（通常是 22）选入限制范围，未在白名单内的 IP 将无法通过 SSH 连接。脚本会检测当前 SSH 客户端 IP，并询问是否临时加入本次白名单，**强烈建议保留默认 `Y`**，否则可能立即断连。

**重要特性**：

- 未选入限制的端口不受影响
- Docker 容器主动访问外网下载不受影响；脚本只限制外部访问本机或经本机端口转发进入服务的入站流量
- **每个端口有独立白名单**：对同一端口再次应用会追加新地区，不会覆盖旧地区；对新端口应用不会影响已有端口
- **lo（本地回环）和 Docker 网桥白名单独立管理**：可以单独添加或清除，不受端口规则影响
- 脚本同时托管 `INPUT` 和 `FORWARD` 链，因此机器上的转发端口也受到同一套按端口隔离的白名单限制

## 工作原理

脚本使用 `iptables` + `ipset` 实现：

- 为每个端口创建独立的 ipset（`wl_<port>`）和 iptables 链（`WL_<port>`）
- ipset 存储该端口的白名单 CIDR 范围，支持高效的大规模 IP 段匹配
- iptables 链在 `INPUT` 和 `FORWARD` 两处插入，拦截入站和转发流量
- lo 接口和 Docker 网桥接口的放行规则优先级最高，插入在所有端口规则之前
- 清除端口规则时，对应的 ipset 和 iptables 链会同时清理
- 元数据文件（`.metadata/manual_ips_<port>.txt`）记录每个端口手动添加的 IP，方便后续管理

## 规则持久化

脚本在应用规则后会自动保存配置，确保重启后规则自动恢复。支持的系统：

- **Debian/Ubuntu**：自动安装 `iptables-persistent` 并保存规则
- **CentOS/RHEL/Fedora**：自动安装 `iptables-services` 并保存规则

其他系统需要手动配置持久化，或重启后重新运行 `apply`。

本地脚本运行时不访问外网。若服务器缺少 `iptables` 或 `ipset`，会自动使用系统默认软件源安装依赖。

## 更新本地 CIDR 数据

在有外网的机器上运行：

```bash
# 增量更新（跳过已存在的文件）
python3 tools/prepare_data.py

# 强制重新下载所有文件
python3 tools/prepare_data.py --force
```

然后把整个目录复制到服务器即可。数据来源：https://github.com/metowolf/iplist

## 测试

运行完整测试套件：

```bash
python3 -m unittest tests/test_firewall_lib.py
```

运行单个测试：

```bash
python3 -m unittest tests.test_firewall_lib.FirewallLibTests.test_collects_unique_cidrs_for_multiple_region_codes
```

检查脚本语法：

```bash
bash -n install.sh && bash -n tools/firewall_lib.sh
python3 -m py_compile tools/region_tool.py
```

## 许可

本项目仅供学习和个人使用。CIDR 数据来源于 [metowolf/iplist](https://github.com/metowolf/iplist)。
