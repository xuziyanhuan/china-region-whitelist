import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
TOOL = ROOT / "tools" / "region_tool.py"
INSTALL_SH = ROOT / "install.sh"
FIREWALL_LIB = ROOT / "tools" / "firewall_lib.sh"


def run_tool(*args: str) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(TOOL),
        "--regions-json",
        str(FIXTURES / "regions.json"),
        "--data-dir",
        str(FIXTURES),
        *args,
    ]
    return subprocess.run(command, text=True, capture_output=True, check=False)


class FirewallLibTests(unittest.TestCase):
    def test_lists_provinces_with_indices(self):
        result = run_tool("list-provinces")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1\t990000\t测试省", result.stdout)
        self.assertIn("2\t980000\t直辖市", result.stdout)

    def test_lists_cities_for_province(self):
        result = run_tool("list-cities", "990000")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1\t990100\t甲市", result.stdout)
        self.assertIn("2\t990200\t乙市", result.stdout)

    def test_collects_unique_cidrs_for_multiple_region_codes(self):
        result = run_tool("collect-cidrs", "990100", "990200")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            ["10.0.0.0/8", "198.51.100.0/24", "203.0.113.0/24"],
        )

    def test_renders_dry_run_commands_with_current_client_ip(self):
        result = run_tool("render-apply", "--ports", "22,80,443", "--client-ip", "198.51.100.88", "990100")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ipset create wl_22 hash:net family inet -exist", result.stdout)
        self.assertIn("ipset add wl_22 10.0.0.0/8 -exist", result.stdout)
        self.assertIn("ipset add wl_22 198.51.100.88 -exist", result.stdout)
        self.assertIn(
            "iptables -C WL_22 -p tcp --dport 22 -m set --match-set wl_22 src -j ACCEPT 2>/dev/null || "
            "iptables -A WL_22 -p tcp --dport 22 -m set --match-set wl_22 src -j ACCEPT",
            result.stdout,
        )
        self.assertIn(
            "iptables -C WL_22 -p tcp --dport 22 -j REJECT 2>/dev/null || "
            "iptables -A WL_22 -p tcp --dport 22 -j REJECT",
            result.stdout,
        )
        self.assertNotIn("ipset flush", result.stdout)
        self.assertNotIn("iptables -F WL_22", result.stdout)

    def test_renders_independent_rules_for_each_port(self):
        result = run_tool("render-apply", "--ports", "22,80,443", "990100")

        self.assertEqual(result.returncode, 0, result.stderr)
        # lo 规则应该只出现一次（在开始处）
        lo_count = result.stdout.count("iptables -C INPUT -i lo -j ACCEPT")
        self.assertEqual(lo_count, 1, "lo rule should appear exactly once for INPUT")
        lo_count = result.stdout.count("iptables -C FORWARD -i lo -j ACCEPT")
        self.assertEqual(lo_count, 1, "lo rule should appear exactly once for FORWARD")
        self.assertNotIn("for iface in docker0", result.stdout)
        self.assertNotIn("-i docker0 -j ACCEPT; fi", result.stdout)

        for port in ("22", "80", "443"):
            with self.subTest(port=port):
                self.assertIn(f"ipset create wl_{port} hash:net family inet -exist", result.stdout)
                self.assertIn(f"iptables -N WL_{port} 2>/dev/null || true", result.stdout)
                self.assertIn(
                    f"iptables -C INPUT -j WL_{port} 2>/dev/null || "
                    f"{{ insert_pos=$(iptables -S INPUT | awk",
                    result.stdout,
                )
                self.assertIn(
                    f"while iptables -C FORWARD -j WL_{port} 2>/dev/null; "
                    f"do iptables -D FORWARD -j WL_{port}; done",
                    result.stdout,
                )
                self.assertIn(
                    f"iptables -C FORWARD -m conntrack --ctstate DNAT -j WL_{port} 2>/dev/null || "
                    f"{{ insert_pos=$(iptables -S FORWARD | awk",
                    result.stdout,
                )
                self.assertIn(
                    f"iptables -C WL_{port} -p udp --dport {port} -m set --match-set wl_{port} src -j ACCEPT 2>/dev/null || "
                    f"iptables -A WL_{port} -p udp --dport {port} -m set --match-set wl_{port} src -j ACCEPT",
                    result.stdout,
                )
        self.assertNotIn("po0_region_whitelist", result.stdout)
        self.assertNotIn("WHITELIST", result.stdout)
        self.assertNotIn("multiport", result.stdout)

    def test_port_jumps_insert_after_loopback_and_docker_bridges(self):
        result = run_tool("render-apply", "--ports", "22", "990100")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('-A INPUT -i lo -j ACCEPT', result.stdout)
        self.assertIn('^-A INPUT -i (docker0|br-[^ ]+) -j ACCEPT$', result.stdout)
        self.assertIn('iptables -I INPUT $insert_pos -j WL_22', result.stdout)
        self.assertIn('^-A FORWARD -i (docker0|br-[^ ]+) -j ACCEPT$', result.stdout)
        self.assertIn('iptables -I FORWARD $insert_pos -m conntrack --ctstate DNAT -j WL_22', result.stdout)

    def test_renders_manual_whitelist_ips(self):
        result = run_tool("render-apply", "--ports", "22", "990100", "198.51.100.7", "203.0.113.0/24")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ipset add wl_22 10.0.0.0/8 -exist", result.stdout)
        self.assertIn("ipset add wl_22 198.51.100.7 -exist", result.stdout)
        self.assertIn("ipset add wl_22 203.0.113.0/24 -exist", result.stdout)

    def test_rejects_invalid_manual_whitelist_ips(self):
        result = run_tool("render-apply", "--ports", "22", "not-an-ip")

        self.assertNotEqual(result.returncode, 0)

    def test_clear_removes_managed_per_port_rules(self):
        result = run_tool("render-clear")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("awk '/^-N WL_/ {print $2}'", result.stdout)
        self.assertIn("while iptables -C FORWARD -j $chain 2>/dev/null; do iptables -D FORWARD -j $chain; done", result.stdout)
        self.assertIn("while iptables -C FORWARD -m conntrack --ctstate DNAT -j $chain 2>/dev/null; do iptables -D FORWARD -m conntrack --ctstate DNAT -j $chain; done", result.stdout)
        self.assertIn("ipset list -name 2>/dev/null | awk '/^wl_/'", result.stdout)
        self.assertNotIn("WHITELIST", result.stdout)
        self.assertNotIn("po0", result.stdout)
        # 清除所有规则时应该删除 lo 和 Docker 网桥规则
        self.assertIn("while iptables -C INPUT -i lo -j ACCEPT 2>/dev/null; do iptables -D INPUT -i lo -j ACCEPT; done", result.stdout)
        self.assertIn("while iptables -C FORWARD -i lo -j ACCEPT 2>/dev/null; do iptables -D FORWARD -i lo -j ACCEPT; done", result.stdout)
        self.assertIn('for iface in docker0 $(ip link show | awk -F\': \' \'/^[0-9]+: br-/ {print $2}\'); do while iptables -C INPUT -i "$iface" -j ACCEPT 2>/dev/null; do iptables -D INPUT -i "$iface" -j ACCEPT; done; done', result.stdout)
        self.assertIn('for iface in docker0 $(ip link show | awk -F\': \' \'/^[0-9]+: br-/ {print $2}\'); do while iptables -C FORWARD -i "$iface" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -i "$iface" -j ACCEPT; done; done', result.stdout)

    def test_clear_specific_ports(self):
        result = run_tool("render-clear", "--ports", "22,80")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("iptables -D INPUT -j WL_22", result.stdout)
        self.assertIn("iptables -D INPUT -j WL_80", result.stdout)
        self.assertIn("iptables -X WL_22", result.stdout)
        self.assertIn("iptables -X WL_80", result.stdout)
        self.assertIn("ipset destroy wl_22", result.stdout)
        self.assertIn("ipset destroy wl_80", result.stdout)
        self.assertNotIn("for chain in", result.stdout)

    def test_exempts_loopback_interface(self):
        result = run_tool("render-apply", "--ports", "22", "990000")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i lo -j ACCEPT", result.stdout)
        self.assertIn("iptables -C FORWARD -i lo -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i lo -j ACCEPT", result.stdout)
        self.assertNotIn("for iface in docker0", result.stdout)
        self.assertNotIn("-i docker0 -j ACCEPT; fi", result.stdout)

    def test_renders_docker_whitelist_rules(self):
        result = run_tool("render-docker-apply", "--interfaces", "docker0,br-9731588312b1")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('for iface in $(iptables -S INPUT | awk \'/^-A INPUT -i (docker0|br-[^ ]+) -j ACCEPT$/ {print $4}\' | sort -u); do while iptables -C INPUT -i "$iface" -j ACCEPT 2>/dev/null; do iptables -D INPUT -i "$iface" -j ACCEPT; done; done', result.stdout)
        self.assertIn('for iface in $(iptables -S FORWARD | awk \'/^-A FORWARD -i (docker0|br-[^ ]+) -j ACCEPT$/ {print $4}\' | sort -u); do while iptables -C FORWARD -i "$iface" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -i "$iface" -j ACCEPT; done; done', result.stdout)
        self.assertIn("if ip link show br-9731588312b1 >/dev/null 2>&1; then iptables -I INPUT 2 -i br-9731588312b1 -j ACCEPT; fi", result.stdout)
        self.assertIn("if ip link show docker0 >/dev/null 2>&1; then iptables -I INPUT 2 -i docker0 -j ACCEPT; fi", result.stdout)
        self.assertIn("iptables -I FORWARD 2 -i br-9731588312b1 -j ACCEPT", result.stdout)

    def test_renders_docker_clear_rules(self):
        result = run_tool("render-docker-clear")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('for iface in $(iptables -S INPUT | awk \'/^-A INPUT -i (docker0|br-[^ ]+) -j ACCEPT$/ {print $4}\' | sort -u); do while iptables -C INPUT -i "$iface" -j ACCEPT 2>/dev/null; do iptables -D INPUT -i "$iface" -j ACCEPT; done; done', result.stdout)
        self.assertIn('for iface in $(iptables -S FORWARD | awk \'/^-A FORWARD -i (docker0|br-[^ ]+) -j ACCEPT$/ {print $4}\' | sort -u); do while iptables -C FORWARD -i "$iface" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -i "$iface" -j ACCEPT; done; done', result.stdout)
        self.assertNotIn("-i lo -j ACCEPT", result.stdout)
        self.assertNotIn("WL_", result.stdout)
        self.assertNotIn("ipset destroy", result.stdout)

    def test_renders_lo_clear_rules(self):
        result = run_tool("render-lo-clear")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("while iptables -C INPUT -i lo -j ACCEPT 2>/dev/null; do iptables -D INPUT -i lo -j ACCEPT; done", result.stdout)
        self.assertIn("while iptables -C FORWARD -i lo -j ACCEPT 2>/dev/null; do iptables -D FORWARD -i lo -j ACCEPT; done", result.stdout)
        self.assertNotIn("docker0", result.stdout)
        self.assertNotIn("WL_", result.stdout)
        self.assertNotIn("ipset destroy", result.stdout)

    def test_rejects_invalid_docker_interfaces(self):
        result = run_tool("render-docker-apply", "--interfaces", "eth0")

        self.assertNotEqual(result.returncode, 0)

    def test_rejects_invalid_ports(self):
        for ports in ("0", "65536", "abc"):
            with self.subTest(ports=ports):
                result = run_tool("render-apply", "--ports", ports, "990100")

                self.assertNotEqual(result.returncode, 0)

    def test_many_ports_render_independent_resources(self):
        ports = ",".join(str(port) for port in range(1, 17))
        result = run_tool("render-apply", "--ports", ports, "990100")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ipset create wl_1 hash:net family inet -exist", result.stdout)
        self.assertIn("ipset create wl_16 hash:net family inet -exist", result.stdout)
        self.assertIn("iptables -N WL_1 2>/dev/null || true", result.stdout)
        self.assertIn("iptables -N WL_16 2>/dev/null || true", result.stdout)
        self.assertNotIn("multiport", result.stdout)

    def test_show_provinces_renders_cli_table(self):
        result = run_tool("show-provinces")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("可选省份", result.stdout)
        self.assertIn("测试省", result.stdout)
        self.assertIn("直辖市", result.stdout)
        self.assertNotIn("990000", result.stdout)

    def test_show_cities_accepts_province_index(self):
        result = run_tool("show-cities", "测试省")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("测试省", result.stdout)
        self.assertIn("全省", result.stdout)
        self.assertIn("甲市", result.stdout)
        self.assertIn("乙市", result.stdout)
        self.assertNotIn("990100", result.stdout)

    def test_resolves_province_and_city_names_to_codes(self):
        province = run_tool("resolve-province", "测试省")
        city = run_tool("resolve-city", "测试省", "甲市")

        self.assertEqual(province.returncode, 0, province.stderr)
        self.assertEqual(city.returncode, 0, city.stderr)
        self.assertEqual(province.stdout.strip(), "990000")
        self.assertEqual(city.stdout.strip(), "990100")

    def test_install_script_does_not_capture_interactive_function_with_mapfile(self):
        script = INSTALL_SH.read_text(encoding="utf-8")

        self.assertNotIn("mapfile -t selected_codes < <(interactive_select_codes)", script)
        self.assertIn("read_from_tty", script)
        self.assertIn("selected_codes=(\"${SELECTED_CODES[@]}\")", script)

    def test_install_script_prompts_for_ports_and_passes_them_to_renderer(self):
        script = INSTALL_SH.read_text(encoding="utf-8")

        self.assertIn("interactive_select_ports()", script)
        self.assertIn("selected_ports_csv=\"$(IFS=,; echo \"${selected_ports[*]}\")\"", script)
        self.assertIn('whitelist_render_apply_commands "${client_ip}" "${selected_ports_csv}" "${manual_ips_csv}" "${selected_codes[@]}"', script)

    def test_install_script_supports_u_menu_shortcut(self):
        script = INSTALL_SH.read_text(encoding="utf-8")

        self.assertIn("省/市白名单一键脚本", script)
        self.assertIn("U|u) show_menu ;;", script)
        self.assertIn("install-shortcut) install_shortcut ;;", script)
        self.assertIn("for target in U u; do", script)
        self.assertIn("cat >\"${target_dir}/${target}\"", script)
        self.assertIn('exec bash "${ROOT}/install.sh" U', script)
        self.assertIn("0. 退出", script)
        self.assertIn("1. 应用白名单规则", script)
        self.assertIn("2. Docker 白名单", script)
        self.assertIn("3. 查看当前托管规则", script)
        self.assertIn("4. 清除本脚本创建的规则和 ipset", script)
        self.assertIn("5. 更新本地 CIDR 数据", script)
        self.assertIn("6. 检查并更新脚本", script)
        self.assertIn("7. 清除规则并删除脚本本体", script)
        self.assertIn("0) echo \"退出。\"; exit 0 ;;", script)
        self.assertIn("1) run_apply_or_dry_run 0", script)
        self.assertIn("2) run_docker_whitelist_menu", script)
        self.assertIn("3) status_rules", script)
        self.assertIn("4) clear_rules", script)
        self.assertIn("5) update_cidr_data ;;", script)
        self.assertIn("6) update_script ;;", script)
        self.assertIn("7) uninstall_all ;;", script)
        self.assertIn("1. 所有 Docker 网桥", script)
        self.assertIn("2. 仅 docker0", script)
        self.assertIn("3. 手动选择", script)
        self.assertIn('whitelist_render_docker_apply_commands "${interfaces_csv}"', script)

    def test_install_script_update_reloads_new_script(self):
        script = INSTALL_SH.read_text(encoding="utf-8")

        self.assertIn("bash \"${parent}/${basename}/install.sh\" install-shortcut", script)
        self.assertIn("exec bash \"${parent}/${basename}/install.sh\" U", script)

    def test_install_script_status_lists_per_port_resources(self):
        script = INSTALL_SH.read_text(encoding="utf-8")

        self.assertIn("== 当前白名单规则 ==", script)
        self.assertIn("== iptables 规则详情 ==", script)
        self.assertIn("awk '/^-N WL_/ {print $2}'", script)

    def test_install_script_skips_unmanaged_clear_ports(self):
        script = INSTALL_SH.read_text(encoding="utf-8")

        self.assertIn("0. 返回上级菜单", script)
        self.assertIn("1. 清除 Docker 白名单", script)
        self.assertIn("2. 清除 lo 白名单", script)
        self.assertIn('if [[ "${selection}" == "0" ]]; then', script)
        self.assertIn('whitelist_render_docker_clear_commands | whitelist_run_rendered_commands', script)
        self.assertIn('whitelist_render_lo_clear_commands | whitelist_run_rendered_commands', script)
        self.assertIn("已清除 lo 白名单。", script)
        self.assertIn('端口 ${requested_port} 当前未由本脚本管理，请重新选择。', script)
        self.assertIn("未选择任何当前托管的端口，返回上级菜单。", script)
        self.assertIn('local -a selected_ports=()', script)
        self.assertIn('done < <(split_user_list "${selection}")', script)
        self.assertIn("return", script)
        self.assertNotIn("未选择任何当前托管的端口。", script)
        self.assertNotIn("IFS=' ' read -r -a selected_ports <<<\"${selection}\"", script)

    def test_install_script_supports_uninstalling_rules_shortcuts_and_project(self):
        script = INSTALL_SH.read_text(encoding="utf-8")

        self.assertIn("uninstall) uninstall_all ;;", script)
        self.assertIn("输入 DELETE", script)
        self.assertIn("正在清除端口规则和 ipset...", script)
        self.assertIn("whitelist_render_clear_commands | whitelist_run_rendered_commands", script)
        self.assertIn("正在清除 lo 白名单...", script)
        self.assertIn("whitelist_render_lo_clear_commands | whitelist_run_rendered_commands", script)
        self.assertIn("正在清除 Docker 网桥白名单...", script)
        self.assertIn("whitelist_render_docker_clear_commands | whitelist_run_rendered_commands", script)
        self.assertIn("rm -f /usr/local/bin/U /usr/local/bin/u", script)
        self.assertIn("rm -rf -- \"${basename}\"", script)

    def test_firewall_lib_renders_docker_apply_commands(self):
        script = FIREWALL_LIB.read_text(encoding="utf-8")

        self.assertIn("whitelist_render_docker_apply_commands()", script)
        self.assertIn('whitelist_region_tool render-docker-apply --interfaces "${interfaces}"', script)
        self.assertIn("whitelist_render_docker_clear_commands()", script)
        self.assertIn("whitelist_region_tool render-docker-clear", script)
        self.assertIn("whitelist_render_lo_clear_commands()", script)
        self.assertIn("whitelist_region_tool render-lo-clear", script)

    def test_firewall_lib_auto_installs_missing_iptables_and_ipset(self):
        script = FIREWALL_LIB.read_text(encoding="utf-8")

        self.assertIn("whitelist_install_dependencies()", script)
        self.assertIn("apt-get update", script)
        self.assertIn("apt-get install -y iptables ipset", script)
        self.assertIn("dnf install -y iptables ipset", script)
        self.assertIn("yum install -y iptables ipset", script)
        self.assertIn("apk add --no-cache iptables ipset", script)
        self.assertIn("zypper --non-interactive install iptables ipset", script)
        self.assertIn("whitelist_install_dependencies", script)


if __name__ == "__main__":
    unittest.main()
