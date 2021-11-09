import common as c
import os
import unittest as t


class TestBasics(t.TestCase):
    def setUp(self):
        pass

    def test_reports_success(self):
        self.assertEqual(c.run("--cmd echo"), 0)

    def test_reports_failure(self):
        self.assertNotEqual(c.run("--cmd rm"), 0)

    def test_reports_exact_errcode(self):
        for val in (0, 1, 254, 255):
            ans = c.run_script(f"exit {val}".encode())
            self.assertEqual(ans.returncode, val)

        if os.sys.platform.startswith("linux"):
            # Linux exitcode is 0-255. Exit 256 should return 0
            ans = c.run_script(b"exit 256")
            self.assertEqual(ans.returncode, 0)
            # Linux exitcode is 0-255. Exit 257 should return 1
            ans = c.run_script(b"exit 257")
            self.assertEqual(ans.returncode, 1)

    def test_run_man(self):
        ans = c.run_script(b"man bash | head -n 1")
        self.assertEqual(ans.returncode, 0)
        self.assertEqual(ans.stdout.split(b"(")[0].lower(), b"bash")

    def test_run_shell_script_with_spaces_in_shebang(self):
        ans = c.run_script(b"./tests/fixtures/02-script-with-spaces-in-shebang.sh")
        self.assertEqual(ans.returncode, 0)
        self.assertEqual(ans.stdout, b"TEST\n")

    def test_run_id_as_root(self):
        ans = c.run_script(b"id", root=True)
        self.assertEqual(ans.returncode, 0)

        parts = ans.stdout.split(b" ")
        self.assertEqual(parts[0], b"uid=0(root)")
        self.assertEqual(parts[1], b"gid=0(root)")
