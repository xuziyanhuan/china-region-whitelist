# 省/市白名单一键脚本

这个项目用于按中国地区 IP 段限制 VPS 入站访问：只有交互选择的省份或城市可以访问指定端口，其他来源访问这些端口会被拒绝。每个端口都有独立白名单；对同一个端口再次应用会追加新的地区，不会覆盖旧地区；对新端口应用不会影响已有端口。脚本同时托管 `INPUT` 和 `FORWARD` 链，因此机器上的转发端口也可以受到同一套按端口隔离的白名单限制。

## 文件

- `install.sh`：服务器上运行的一键脚本
- `data/regions.json`：省市索引
- `data/regions/*.txt`：本地 CIDR 段
- `tools/region_tool.py`：本地数据解析和命令生成工具
- `vendor/ipipfree.ipdb`：本地 ipdb 参考文件

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

打开数字菜单：

```bash
U
```

正式运行：

```bash
sudo bash install.sh apply
```

脚本会直接列出所有省份，例如 `1.北京市`、`19.广东省`。选择省份后会继续列出该省全部城市，例如 `1.广州市`、`3.深圳市`。你可以输入编号，也可以直接输入名称；多个选择用空格、英文逗号、中文逗号或顿号分隔。

如果不想选择省/市，也可以在省份选择时输入 `0`，然后手动输入白名单 IP 或 CIDR，例如 `1.2.3.4 192.168.1.0/24`。选择了省/市后，也可以继续额外添加手动 IP。

地区或手动 IP 选择完成后需要输入要限制的端口，例如 `22 80 443`。如果想移除旧地区或从零开始配置，先运行 `clear` 再重新应用。

查看状态：

```bash
sudo bash install.sh status
```

清除规则：

```bash
sudo bash install.sh clear
```

清除规则并删除脚本本体：

```bash
sudo bash install.sh uninstall
```

该命令会要求输入 `DELETE` 确认，然后清除本脚本管理的规则、删除 `/usr/local/bin/U` 和 `/usr/local/bin/u`，并删除当前项目目录。

## 安全提示

`apply` 会拒绝所有未命中白名单来源对**你选定端口**的 TCP/UDP 访问。如果把 SSH 端口（通常是 22）选入限制范围，未在白名单内的 IP 将无法通过 SSH 连接。脚本会检测当前 SSH 客户端 IP，并询问是否临时加入本次白名单，**强烈建议保留默认 `Y`**，否则可能立即断连。

未选入限制的端口不受影响。Docker 容器主动访问外网下载不受影响；脚本只限制外部访问本机或经本机端口转发进入服务的入站流量。

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
