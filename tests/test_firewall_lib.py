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
        for port in ("22", "80", "443"):
            with self.subTest(port=port):
                self.assertIn(f"ipset create wl_{port} hash:net family inet -exist", result.stdout)
                self.assertIn(f"iptables -N WL_{port} 2>/dev/null || true", result.stdout)
                self.assertIn(
                    f"iptables -C INPUT -j WL_{port} 2>/dev/null || "
                    f"iptables -I INPUT 1 -j WL_{port}",
                    result.stdout,
                )
                self.assertIn(
                    f"iptables -C FORWARD -j WL_{port} 2>/dev/null || "
                    f"iptables -I FORWARD 1 -j WL_{port}",
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
        self.assertIn("ipset list -name 2>/dev/null | awk '/^wl_/'", result.stdout)
        self.assertNotIn("WHITELIST", result.stdout)
        self.assertNotIn("po0", result.stdout)

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
        self.assertIn("whitelist_render_apply_commands \"${client_ip}\" \"${selected_ports_csv}\" \"${selected_codes[@]}\"", script)

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
        self.assertIn("2. 更新本地 CIDR 数据", script)
        self.assertIn("3. 查看当前托管规则", script)
        self.assertIn("4. 清除本脚本创建的规则和 ipset", script)
        self.assertIn("5. 检查并更新脚本", script)
        self.assertIn("6. 清除规则并删除脚本本体", script)
        self.assertIn("0) echo \"退出。\"; exit 0 ;;", script)
        self.assertIn("1) run_apply_or_dry_run 0", script)
        self.assertIn("2) update_cidr_data ;;", script)
        self.assertIn("3) status_rules", script)
        self.assertIn("4) clear_rules", script)
        self.assertIn("5) update_script ;;", script)
        self.assertIn("6) uninstall_all ;;", script)

    def test_install_script_status_lists_per_port_resources(self):
        script = INSTALL_SH.read_text(encoding="utf-8")

        self.assertIn("== 当前白名单规则 ==", script)
        self.assertIn("== iptables 规则详情 ==", script)
        self.assertIn("awk '/^-N WL_/ {print $2}'", script)

    def test_install_script_supports_uninstalling_rules_shortcuts_and_project(self):
        script = INSTALL_SH.read_text(encoding="utf-8")

        self.assertIn("uninstall) uninstall_all ;;", script)
        self.assertIn("输入 DELETE", script)
        self.assertIn("whitelist_render_clear_commands | whitelist_run_rendered_commands", script)
        self.assertIn("rm -f /usr/local/bin/U /usr/local/bin/u", script)
        self.assertIn("rm -rf -- \"${basename}\"", script)

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
