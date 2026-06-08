#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${ROOT}/tools/firewall_lib.sh"

usage() {
  cat <<'EOF'
省/市白名单一键脚本

用法：
  U                    安装快捷命令后，直接打开数字菜单
  ./install.sh install-shortcut  安装 U/u 快捷命令
  ./install.sh U       打开数字菜单
  ./install.sh apply   交互选择地区并应用防火墙
  ./install.sh status  查看当前托管规则
  ./install.sh clear   清除本脚本创建的规则和 ipset
  ./install.sh uninstall  清除本脚本规则并删除项目目录

说明：
  apply 只会限制所选 TCP/UDP 端口；未命中白名单的来源访问这些端口会被拒绝。
  可在数字菜单中选择"更新本地 CIDR 数据"从 GitHub 重新下载最新地区数据。
EOF
}

pick_by_indices() {
  local prompt="$1"
  local max="$2"
  local input
  while true; do
    read -r -p "${prompt}" input
    input="${input//,/ }"
    [[ -n "${input}" ]] || continue
    local ok=1
    for value in ${input}; do
      if ! [[ "${value}" =~ ^[0-9]+$ ]] || (( value < 1 || value > max )); then
        ok=0
      fi
    done
    if [[ "${ok}" -eq 1 ]]; then
      echo "${input}"
      return
    fi
    echo "输入无效，请输入 1-${max} 范围内的编号，可用空格或逗号分隔。"
  done
}

split_user_list() {
  local input="$1"
  input="${input//,/ }"
  input="${input//，/ }"
  input="${input//、/ }"
  printf '%s\n' ${input}
}

read_from_tty() {
  local prompt="$1"
  local value
  if [[ -r /dev/tty ]]; then
    read -r -p "${prompt}" value < /dev/tty
  else
    read -r -p "${prompt}" value
  fi
  printf '%s\n' "${value}"
}

# 去重列表：输入空格分隔的字符串，输出去重后的数组
deduplicate_list() {
  local -n output_array="$1"
  shift
  local seen=" " item
  for item in "$@"; do
    if [[ "${seen}" != *" ${item} "* ]]; then
      output_array+=("${item}")
      seen+="${item} "
    fi
  done
}

# 确认操作：提示用户确认，返回 0 继续，返回 1 取消
confirm_action() {
  local prompt="${1:-确认继续？[Y/n]: }"
  local answer
  read -r -p "${prompt}" answer
  case "${answer:-Y}" in
    n|N|no|NO) return 1 ;;
    *) return 0 ;;
  esac
}

code_at_index() {
  local rows="$1"
  local index="$2"
  awk -F '\t' -v wanted="${index}" '$1 == wanted {print $2}' <<<"${rows}"
}

interactive_select_codes() {
  SELECTED_CODES=()
  echo "请选择省/自治区/直辖市：" >&2
  whitelist_show_provinces >&2
  echo >&2
  echo "输入编号或省份名称，多个用空格/逗号分隔，例如：1 2 广东省 江苏省" >&2
  echo "输入 0 跳过省/市选择，直接手动输入 IP" >&2

  local province_input
  province_input="$(read_from_tty "省份: ")"
  [[ -n "${province_input}" ]] || {
    echo "未输入省份。" >&2
    exit 1
  }

  # 如果输入 0，跳过省市选择
  if [[ "${province_input}" == "0" ]]; then
    return
  fi

  local province_selector province_code city_input city_selector city_code
  while IFS= read -r province_selector; do
    [[ -n "${province_selector}" ]] || continue
    province_code="$(whitelist_resolve_province "${province_selector}")"

    echo >&2
    whitelist_show_cities "${province_code}" >&2
    echo "输入 0/全省/全市，或输入城市编号/城市名称，多个用空格/逗号分隔，例如：1 2 深圳市 广州市" >&2
    city_input="$(read_from_tty "城市: ")"
    [[ -n "${city_input}" ]] || {
      echo "未输入城市选择。" >&2
      exit 1
    }

    if [[ "${city_input}" == "0" || "${city_input}" == "全省" || "${city_input}" == "全市" ]]; then
      SELECTED_CODES+=("${province_code}")
    else
      while IFS= read -r city_selector; do
        [[ -n "${city_selector}" ]] || continue
        city_code="$(whitelist_resolve_city "${province_code}" "${city_selector}")"
        SELECTED_CODES+=("${city_code}")
      done < <(split_user_list "${city_input}")
    fi
  done < <(split_user_list "${province_input}")
}

interactive_input_manual_ips() {
  MANUAL_IPS=()
  echo >&2
  echo "请输入白名单 IP 或 CIDR，多个用空格/逗号分隔，例如：1.2.3.4 192.168.1.0/24" >&2
  echo "留空跳过" >&2

  local ip_input
  ip_input="$(read_from_tty "IP/CIDR: ")"

  if [[ -z "${ip_input}" ]]; then
    return
  fi

  local ip_or_cidr
  while IFS= read -r ip_or_cidr; do
    [[ -n "${ip_or_cidr}" ]] || continue

    # 简单验证 IP 或 CIDR 格式
    if [[ "${ip_or_cidr}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
      MANUAL_IPS+=("${ip_or_cidr}")
    else
      echo "警告：跳过无效的 IP/CIDR：${ip_or_cidr}" >&2
    fi
  done < <(split_user_list "${ip_input}")
}

interactive_select_ports() {
  SELECTED_PORTS=()
  echo >&2
  echo "请输入需要限制的端口，多个用空格/逗号分隔，例如：22 80 443" >&2

  local port_input port port_number
  port_input="$(read_from_tty "端口: ")"
  [[ -n "${port_input}" ]] || {
    echo "未输入端口。" >&2
    exit 1
  }

  local -a validated_ports=()
  while IFS= read -r port; do
    [[ -n "${port}" ]] || continue
    if ! [[ "${port}" =~ ^[0-9]+$ ]] || (( ${#port} > 5 )); then
      echo "端口无效：${port}。请输入 1-65535 范围内的数字。" >&2
      exit 1
    fi
    port_number=$((10#${port}))
    if (( port_number < 1 || port_number > 65535 )); then
      echo "端口无效：${port}。请输入 1-65535 范围内的数字。" >&2
      exit 1
    fi
    validated_ports+=("${port_number}")
  done < <(split_user_list "${port_input}")

  deduplicate_list SELECTED_PORTS "${validated_ports[@]}"

  if [[ "${#SELECTED_PORTS[@]}" -eq 0 ]]; then
    echo "未输入端口。" >&2
    exit 1
  fi
}

confirm_client_ip() {
  local client_ip="$1"
  shift
  local -a ports=("$@")

  if [[ -z "${client_ip}" ]]; then
    echo ""
    return
  fi

  # 只在选择了端口 22 时才询问
  local has_ssh=0
  for port in "${ports[@]}"; do
    if [[ "${port}" == "22" ]]; then
      has_ssh=1
      break
    fi
  done

  if [[ "${has_ssh}" -eq 0 ]]; then
    echo ""
    return
  fi

  echo "检测到当前 SSH 客户端 IP：${client_ip}" >&2
  read -r -p "是否临时加入本次白名单以避免断连？[Y/n] " answer
  case "${answer:-Y}" in
    y|Y|yes|YES) echo "${client_ip}" ;;
    *) echo "" ;;
  esac
}

run_apply_or_dry_run() {
  local dry_run="$1"
  local -a selected_codes selected_ports manual_ips
  local selected_ports_csv
  interactive_select_codes
  selected_codes=("${SELECTED_CODES[@]}")

  # 如果没有选择地区，询问是否手动输入 IP
  if [[ "${#selected_codes[@]}" -eq 0 ]]; then
    interactive_input_manual_ips
    manual_ips=("${MANUAL_IPS[@]}")

    if [[ "${#manual_ips[@]}" -eq 0 ]]; then
      echo "未选择任何地区或输入任何 IP。" >&2
      exit 1
    fi
  else
    # 已选择地区，询问是否额外添加手动 IP
    interactive_input_manual_ips
    manual_ips=("${MANUAL_IPS[@]}")
  fi

  interactive_select_ports
  selected_ports=("${SELECTED_PORTS[@]}")
  selected_ports_csv="$(IFS=,; echo "${selected_ports[*]}")"

  local client_ip
  client_ip="$(confirm_client_ip "$(whitelist_detect_ssh_client_ip)" "${selected_ports[@]}")"

  echo
  if [[ "${#selected_codes[@]}" -gt 0 ]]; then
    echo "将使用以下地区代码：${selected_codes[*]}"
  fi
  if [[ "${#manual_ips[@]}" -gt 0 ]]; then
    echo "将添加以下手动 IP：${manual_ips[*]}"
  fi
  echo "将限制以下 TCP/UDP 端口：${selected_ports_csv}"
  echo

  if [[ "${dry_run}" == "1" ]]; then
    local manual_ips_csv
    manual_ips_csv="$(IFS=,; echo "${manual_ips[*]}")"
    whitelist_render_apply_commands "${client_ip}" "${selected_ports_csv}" "${manual_ips_csv}" "${selected_codes[@]}"
    return
  fi

  whitelist_require_root
  whitelist_require_commands
  echo "即将应用规则：未命中白名单的来源访问所选 TCP/UDP 端口会被拒绝。"
  if ! confirm_action "确认继续？[Y/n]: "; then
    echo "已取消。"
    exit 0
  fi
  local manual_ips_csv
  manual_ips_csv="$(IFS=,; echo "${manual_ips[*]}")"
  whitelist_render_apply_commands "${client_ip}" "${selected_ports_csv}" "${manual_ips_csv}" "${selected_codes[@]}" | whitelist_run_rendered_commands
  echo "规则已应用。"

  # 持久化规则
  persist_rules
}

run_docker_whitelist_menu() {
  whitelist_require_root
  whitelist_require_commands

  local -a docker_bridges selected_bridges
  mapfile -t docker_bridges < <(
    {
      ip link show docker0 >/dev/null 2>&1 && printf '%s\n' docker0
      ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^br-/ {print $2}'
    } | awk '!seen[$0]++'
  )

  if [[ "${#docker_bridges[@]}" -eq 0 ]]; then
    echo "未发现 docker0 或 br-* Docker 网桥。"
    return
  fi

  echo
  echo "Docker 白名单："
  echo "1. 所有 Docker 网桥"
  echo "2. 仅 docker0"
  echo "3. 手动选择"
  local docker_choice
  docker_choice="$(read_from_tty "请输入数字: ")"

  case "${docker_choice}" in
    1)
      selected_bridges=("${docker_bridges[@]}")
      ;;
    2)
      if ip link show docker0 >/dev/null 2>&1; then
        selected_bridges=("docker0")
      else
        echo "当前不存在 docker0。"
        return
      fi
      ;;
    3)
      echo "当前 Docker 网桥："
      local index
      for index in "${!docker_bridges[@]}"; do
        echo "$((index + 1)). ${docker_bridges[index]}"
      done
      local selection selected_index bridge
      local -a validated_bridges=()
      selection="$(read_from_tty "请选择网桥编号（多个用空格/逗号分隔）: ")"
      while IFS= read -r selected_index; do
        [[ -n "${selected_index}" ]] || continue
        if ! [[ "${selected_index}" =~ ^[0-9]+$ ]] || (( selected_index < 1 || selected_index > ${#docker_bridges[@]} )); then
          echo "输入无效：${selected_index}。"
          return
        fi
        bridge="${docker_bridges[$((selected_index - 1))]}"
        validated_bridges+=("${bridge}")
      done < <(split_user_list "${selection}")
      deduplicate_list selected_bridges "${validated_bridges[@]}"
      ;;
    *)
      echo "输入无效。"
      return
      ;;
  esac

  if [[ "${#selected_bridges[@]}" -eq 0 ]]; then
    echo "未选择任何 Docker 网桥。"
    return
  fi

  echo "将写入以下 Docker 网桥白名单：${selected_bridges[*]}"
  if ! confirm_action; then
    echo "已取消。"
    return
  fi

  local interfaces_csv
  interfaces_csv="$(IFS=,; echo "${selected_bridges[*]}")"
  whitelist_render_docker_apply_commands "${interfaces_csv}" | whitelist_run_rendered_commands
  echo "Docker 白名单已应用。"
  persist_rules
}

persist_rules() {
  echo
  echo "正在保存规则以便重启后自动恢复..."

  # 检测系统类型并安装 iptables-persistent
  if command -v apt-get >/dev/null 2>&1; then
    # 安装 iptables-persistent 和 ipset-persistent
    local need_install=0
    if ! dpkg -l | grep -q iptables-persistent; then
      need_install=1
    fi
    if ! dpkg -l | grep -q ipset-persistent; then
      need_install=1
    fi

    if [ "$need_install" -eq 1 ]; then
      echo "检测到 Debian/Ubuntu 系统，正在安装持久化工具..."
      DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent ipset-persistent >/dev/null 2>&1 || {
        echo "警告：持久化工具安装失败，规则不会持久化。" >&2
        return
      }
    fi

    # 保存 iptables 和 ipset 规则
    netfilter-persistent save >/dev/null 2>&1 || {
      iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
      ipset save > /etc/iptables/ipsets 2>/dev/null || true
    }

    echo "规则已保存，重启后将自动恢复。"

  elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
    # CentOS/RHEL/Fedora
    if ! rpm -q iptables-services >/dev/null 2>&1; then
      echo "检测到 RHEL/CentOS 系统，正在安装 iptables-services..."
      (yum install -y iptables-services || dnf install -y iptables-services) >/dev/null 2>&1 || {
        echo "警告：iptables-services 安装失败，规则不会持久化。" >&2
        return
      }
      systemctl enable iptables >/dev/null 2>&1 || true
    fi
    service iptables save >/dev/null 2>&1 || iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
    ipset save > /etc/sysconfig/ipset 2>/dev/null || true

    # CentOS/RHEL 的 ipset 服务
    if rpm -q ipset-service >/dev/null 2>&1 || (yum install -y ipset-service || dnf install -y ipset-service) >/dev/null 2>&1; then
      systemctl enable ipset >/dev/null 2>&1 || true
    fi

    echo "规则已保存，重启后将自动恢复。"
  else
    echo "警告：未识别的系统类型，无法自动持久化规则。" >&2
    echo "请手动配置规则持久化，或重启后重新运行 apply。" >&2
  fi
}

status_rules() {
  whitelist_require_root

  echo "== 当前白名单规则 =="
  if command -v ipset >/dev/null 2>&1 && command -v iptables >/dev/null 2>&1; then
    python3 "${ROOT}/tools/region_tool.py" render-status --metadata-dir "${ROOT}/.metadata"
  else
    echo "ipset 或 iptables 未安装"
    return
  fi

  echo
  echo "== iptables 规则详情 =="
  if command -v iptables >/dev/null 2>&1; then
    local chain_name
    while IFS= read -r chain_name; do
      [[ -n "${chain_name}" ]] || continue
      iptables -S "${chain_name}" 2>/dev/null || true
      echo
    done < <(iptables -S 2>/dev/null | awk '/^-N WL_/ {print $2}' || true)
  else
    echo "iptables 未安装"
  fi
}

clear_rules() {
  whitelist_require_root
  whitelist_require_commands

  while true; do
    local -a managed_ports
    mapfile -t managed_ports < <(whitelist_list_managed_ports)

    echo "当前管理的端口："
    if [[ "${#managed_ports[@]}" -eq 0 ]]; then
      echo "  （无）"
    else
      local port
      for port in "${managed_ports[@]}"; do
        echo "  - ${port}"
      done
    fi
    echo
    echo "清除选项："
    echo "0. 返回上级菜单"
    echo "1. 清除 Docker 白名单"
    echo "2. 清除 lo 白名单"
    echo "ALL. 清除全部端口规则、lo 和 Docker 白名单"
    echo

    local selection
    read -r -p "请选择要清除的端口（多个用空格/逗号分隔，输入 0 返回）: " selection

    if [[ "${selection}" == "0" ]]; then
      echo "返回上级菜单。"
      return
    fi

    if [[ "${selection}" == "1" ]]; then
      echo "将清除 Docker 白名单..."
      whitelist_render_docker_clear_commands | whitelist_run_rendered_commands
      echo "已清除 Docker 白名单。"
      persist_rules
      return
    fi

    if [[ "${selection}" == "2" ]]; then
      echo "将清除 lo 白名单..."
      whitelist_render_lo_clear_commands | whitelist_run_rendered_commands
      echo "已清除 lo 白名单。"
      persist_rules
      return
    fi

    if [[ "${selection^^}" == "ALL" ]]; then
      if [[ "${#managed_ports[@]}" -eq 0 ]]; then
        echo "当前没有管理任何端口规则，将只清除 lo 和 Docker 白名单..."
      else
        echo "将清除全部端口规则..."
      fi
      whitelist_render_clear_commands | whitelist_run_rendered_commands
      if [[ -d "${ROOT}/.metadata" ]]; then
        rm -f "${ROOT}/.metadata/manual_ips_"*.txt
        echo "已清除元数据文件。"
      fi
      echo "已清除全部规则。"
      persist_rules
      return
    fi

    if [[ "${#managed_ports[@]}" -eq 0 ]]; then
      echo "当前没有管理任何端口规则，请选择 1 清除 Docker 白名单、2 清除 lo 白名单或 0 返回。"
      return
    fi

    local -a selected_ports=()
    local -a validated_ports=()
    local requested_port managed_port found skipped=0
    while IFS= read -r requested_port; do
      [[ -n "${requested_port}" ]] || continue
      found=0
      for managed_port in "${managed_ports[@]}"; do
        if [[ "${requested_port}" == "${managed_port}" ]]; then
          found=1
          break
        fi
      done
      if [[ "${found}" -eq 1 ]]; then
        validated_ports+=("${requested_port}")
      else
        echo "端口 ${requested_port} 当前未由本脚本管理，请重新选择。"
        skipped=1
      fi
    done < <(split_user_list "${selection}")

    deduplicate_list selected_ports "${validated_ports[@]}"

    if [[ "${skipped}" -eq 1 || "${#selected_ports[@]}" -eq 0 ]]; then
      echo "未选择任何当前托管的端口，返回上级菜单。"
      return
    fi

    echo "将清除以下端口的规则：${selected_ports[*]}"
    local ports_csv
    ports_csv="$(IFS=,; echo "${selected_ports[*]}")"
    whitelist_render_clear_commands --ports "${ports_csv}" | whitelist_run_rendered_commands
    for port in "${selected_ports[@]}"; do
      if [[ -f "${ROOT}/.metadata/manual_ips_${port}.txt" ]]; then
        rm -f "${ROOT}/.metadata/manual_ips_${port}.txt"
      fi
    done
    echo "已清除元数据文件。"

    local -a remaining_ports
    mapfile -t remaining_ports < <(whitelist_list_managed_ports)
    if [[ "${#remaining_ports[@]}" -eq 0 ]]; then
      echo "所有端口规则已清除，正在删除 lo 和 Docker 网桥接口规则..."
      whitelist_render_clear_commands | whitelist_run_rendered_commands
    fi

    echo "已清除选定的规则。"
    persist_rules
    return
  done
}

uninstall_all() {
  whitelist_require_root
  echo "此操作将清除本脚本管理的规则，删除 U/u 快捷命令，并删除项目目录：${ROOT}"
  read -r -p "确认继续？输入 DELETE: " confirm
  if [[ "${confirm}" != "DELETE" ]]; then
    echo "已取消。"
    exit 0
  fi

  whitelist_require_commands
  echo "正在清除端口规则和 ipset..."
  whitelist_render_clear_commands | whitelist_run_rendered_commands
  echo "正在清除 lo 白名单..."
  whitelist_render_lo_clear_commands | whitelist_run_rendered_commands
  echo "正在清除 Docker 网桥白名单..."
  whitelist_render_docker_clear_commands | whitelist_run_rendered_commands
  if [[ -d "${ROOT}/.metadata" ]]; then
    rm -f "${ROOT}/.metadata/manual_ips_"*.txt
  fi
  rm -f /usr/local/bin/U /usr/local/bin/u
  local parent basename
  parent="$(dirname "${ROOT}")"
  basename="$(basename "${ROOT}")"
  cd "${parent}"
  rm -rf -- "${basename}"
  echo "已清除规则、快捷命令和项目目录。"
  echo "提示：如果 U/u 命令仍显示错误，请运行：hash -r"
}

update_cidr_data() {
  echo "此操作将从 GitHub 重新下载所有省市 CIDR 数据。"
  echo "数据来源：https://github.com/metowolf/iplist"
  read -r -p "确认继续？[Y/n]: " confirm
  case "${confirm:-Y}" in
    y|Y|yes|YES) ;;
    *) echo "已取消。"; return ;;
  esac

  if ! command -v python3 &>/dev/null; then
    echo "错误：需要 python3 来更新数据。" >&2
    return
  fi

  python3 "${ROOT}/tools/prepare_data.py" --force
  echo "CIDR 数据更新完成。"
  read -r -p "按回车键返回菜单..."
}

update_script() {
  echo "正在检查更新..."

  if ! command -v curl &>/dev/null; then
    echo "错误：需要 curl 来检查更新。" >&2
    read -r -p "按回车键返回菜单..."
    return
  fi

  local current_version=""
  local latest_version=""
  local remote_version_info=""

  # 读取本地版本号
  if [[ -f "${ROOT}/VERSION" ]]; then
    current_version=$(cat "${ROOT}/VERSION" 2>/dev/null | tr -d '[:space:]' || echo "")
  fi

  # 获取远程版本信息（VERSION 文件内容）
  remote_version_info=$(curl -sL https://raw.githubusercontent.com/xuziyanhuan/china-region-whitelist/main/VERSION 2>/dev/null | tr -d '[:space:]' || echo "")

  if [[ -z "${remote_version_info}" ]]; then
    echo "无法获取远程版本信息，请检查网络连接。"
    read -r -p "按回车键返回菜单..."
    return
  fi

  latest_version="${remote_version_info}"

  if [[ -n "${current_version}" && "${current_version}" == "${latest_version}" ]]; then
    echo "已是最新版本 v${current_version}，无需更新。"
    read -r -p "按回车键返回菜单..."
    return
  fi

  echo "发现新版本！"
  if [[ -n "${current_version}" ]]; then
    echo "当前版本: v${current_version}"
  else
    echo "当前版本: 未知"
  fi
  echo "最新版本: v${latest_version}"
  echo
  read -r -p "是否更新到最新版本？[Y/n]: " confirm
  case "${confirm:-Y}" in
    y|Y|yes|YES) ;;
    *) echo "已取消。"; read -r -p "按回车键返回菜单..."; return ;;
  esac

  local temp_dir
  temp_dir=$(mktemp -d)

  echo "正在下载最新版本..."
  if ! curl -sL https://github.com/xuziyanhuan/china-region-whitelist/archive/refs/heads/main.tar.gz | tar xz -C "${temp_dir}"; then
    echo "下载失败。" >&2
    rm -rf "${temp_dir}"
    read -r -p "按回车键返回菜单..."
    return
  fi

  local parent basename
  parent="$(dirname "${ROOT}")"
  basename="$(basename "${ROOT}")"

  echo "正在更新脚本..."
  # 备份当前目录
  local backup_dir="${ROOT}.backup.$(date +%Y%m%d_%H%M%S)"
  mv "${ROOT}" "${backup_dir}" 2>/dev/null || true

  # 移动新版本到当前位置
  mv "${temp_dir}/china-region-whitelist-main" "${parent}/${basename}"

  rm -rf "${temp_dir}"

  # 更新成功，清理备份
  rm -rf "${backup_dir}"

  # 重新安装快捷命令并切换到新版脚本
  bash "${parent}/${basename}/install.sh" install-shortcut

  # 清理 shell 命令缓存
  hash -r 2>/dev/null || true

  echo "更新完成！当前版本: v${latest_version}"
  echo "提示：已有的防火墙规则不受影响，继续生效。"
  sleep 1
  exec bash "${parent}/${basename}/install.sh" U
}

show_menu() {
  while true; do
    clear
    cat <<'EOF'
省/市白名单一键脚本

请选择操作：
0. 退出
1. 应用白名单规则
2. Docker 白名单
3. 查看当前托管规则
4. 清除本脚本创建的规则和 ipset
5. 更新本地 CIDR 数据
6. 检查并更新脚本
7. 清除规则并删除脚本本体
EOF

    local choice
    choice="$(read_from_tty "请输入数字: ")"
    case "${choice}" in
      0) echo "退出。"; exit 0 ;;
      1) run_apply_or_dry_run 0; read -r -p "按回车键返回菜单..." ;;
      2) run_docker_whitelist_menu; read -r -p "按回车键返回菜单..." ;;
      3) status_rules; read -r -p "按回车键返回菜单..." ;;
      4) clear_rules; read -r -p "按回车键返回菜单..." ;;
      5) update_cidr_data ;;
      6) update_script ;;
      7) uninstall_all ;;
      *) echo "输入无效，请输入 0-7。"; sleep 0.5 ;;
    esac
  done
}

install_shortcut() {
  whitelist_require_root
  local target_dir="/usr/local/bin"
  local target
  mkdir -p "${target_dir}"
  for target in U u; do
    cat >"${target_dir}/${target}" <<EOF
#!/usr/bin/env bash
exec bash "${ROOT}/install.sh" U "\$@"
EOF
    chmod 755 "${target_dir}/${target}"
  done
  echo "已安装快捷命令：U 和 u。"
}

main() {
  local command="${1:-apply}"
  case "${command}" in
    U|u) show_menu ;;
    install-shortcut) install_shortcut ;;
    apply) run_apply_or_dry_run 0 ;;
    status) status_rules ;;
    clear) clear_rules ;;
    uninstall) uninstall_all ;;
    -h|--help|help) usage ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
