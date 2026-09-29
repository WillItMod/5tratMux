"""Exercise updater resolver argv and pre-mutation guards without Docker."""
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "5tratmux-update"


class DNSUpdaterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.library = self.root / "functions.sh"
        self.library.write_text(SOURCE.read_text().split('case "${1:---check}" in')[0])
        self.env = dict(os.environ, MUX_CONTAINER_NAME="dns-test",
                        MUX_UPDATER_ENV_FILE=str(self.root / "absent.env"),
                        MUX_DNS_CONFIG_FILE=str(self.root / "dns.json"),
                        MUX_DNS_OPERATION_FILE=str(self.root / "operation.json"),
                        MUX_LIFECYCLE_LOCK_FILE=str(self.root / "lifecycle.lock"),
                        MUX_STATUS_FILE=str(self.root / "status.json"),
                        MUX_RUNTIME_DIR=str(self.root),
                        MUX_DNS_PRIMARY="1.1.1.1", MUX_DNS_SECONDARY="8.8.8.8")

    def run_shell(self, code):
        return subprocess.run(["bash", "-c", 'source "$1"\n' + code, "test", str(self.library)],
                              env=self.env, text=True, capture_output=True)

    def config(self, payload):
        Path(self.env["MUX_DNS_CONFIG_FILE"]).write_text(json.dumps(payload))

    def test_default_and_legacy_resolvers(self):
        self.env["MUX_DNS_PRIMARY"] = "10.10.10.1"
        self.assertEqual(self.run_shell("configured_dns_servers").stdout.splitlines(), ["10.10.10.1", "8.8.8.8"])
        self.config({"mode": "default", "servers": []})
        self.assertEqual(self.run_shell("configured_dns_servers").stdout.splitlines(), ["1.1.1.1", "8.8.8.8"])

    def test_custom_ipv4_ipv6_become_separate_docker_arguments(self):
        self.config({"mode": "custom", "servers": ["10.10.10.1", "2606:4700:4700::1111", "10.10.10.1"]})
        result = self.run_shell('docker() { printf "%s\\0" "$@" > "$MUX_RUNTIME_DIR/argv"; }; container_mounts() { printf -- "--mount\\ntype=bind,src=/test,dst=/test\\n"; }; start_container sha256:verified MAIN')
        self.assertEqual(result.returncode, 0, result.stderr)
        argv = (self.root / "argv").read_text().split("\0")
        self.assertEqual([argv[i + 1] for i, arg in enumerate(argv) if arg == "--dns"],
                         ["10.10.10.1", "2606:4700:4700::1111"])
        self.assertIn("sha256:verified", argv)
        self.assertIn("--read-only", argv)

    def test_invalid_settings_cannot_stop_or_start_container(self):
        for servers in [[], ["0.0.0.0"], ["224.0.0.1"], ["255.255.255.255"],
                        ["resolver.example"], ["$(touch /tmp/invalid)"], ["::%lo"],
                        ["1.1.1.1"] * 4]:
            with self.subTest(servers=servers):
                self.config({"mode": "custom", "servers": servers})
                result = self.run_shell('require_root() { :; }; require_commands() { :; }; write_public_key() { :; }; ensure_config() { :; }; docker() { touch "$MUX_RUNTIME_DIR/docker-called"; }; install_release')
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "docker-called").exists())

    @unittest.skipUnless(shutil.which("flock"), "requires Linux flock")
    def test_concurrent_apply_does_not_mutate_or_overwrite_status(self):
        status = self.root / "status.json"
        status.write_text('{"phase":"installing"}')
        with open(self.env["MUX_LIFECYCLE_LOCK_FILE"], "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_shell('require_root() { :; }; mutate() { touch "$MUX_RUNTIME_DIR/mutated"; }; with_lifecycle_lock mutate')
        self.assertEqual(result.returncode, 75)
        self.assertFalse((self.root / "mutated").exists())
        self.assertEqual(status.read_text(), '{"phase":"installing"}')

    @unittest.skipUnless(shutil.which("flock"), "requires Linux flock")
    def test_interrupted_apply_blocks_restart_until_reconciled(self):
        for state in [{"applying": True}, {"rollback": "requires_inspection"}]:
            Path(self.env["MUX_DNS_OPERATION_FILE"]).write_text(json.dumps(state))
            result = self.run_shell('require_root() { :; }; mutate() { touch "$MUX_RUNTIME_DIR/mutated"; }; with_lifecycle_lock mutate')
            self.assertEqual(result.returncode, 75)
            self.assertFalse((self.root / "mutated").exists())
        Path(self.env["MUX_DNS_OPERATION_FILE"]).write_text('{"applying":false,"rollback":null}')
        result = self.run_shell('require_root() { :; }; mutate() { touch "$MUX_RUNTIME_DIR/mutated"; }; with_lifecycle_lock mutate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "mutated").exists())


if __name__ == "__main__":
    unittest.main()
