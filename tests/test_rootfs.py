import common as c
import os
import tarfile
import unittest as t


STAGING = "tests/fixtures/staging"


class TestRootFs(t.TestCase):
    maxDiff = 8192

    def setUp(self):
        init_ok = os.system(
            f"""
            pwd >&2;
            rm -rf {STAGING}; 
            mkdir -p {STAGING}; 
            cd {STAGING};
            rm -f ../result.tar;
            """
        )
        self.assertEqual(init_ok, 0)

    def _setup_untar(self, tar_name):
        init_ok = os.system(
            f"""
            cd {STAGING};
            tar xf ../{tar_name};
            """
        )
        self.assertEqual(init_ok, 0)

    def _setup_untar_in_container(self, tar_name, **kwargs):
        ans = c.run_script(
            f"""
            cd {STAGING};
            tar xf ../{tar_name};
            """.encode(),
            **kwargs,
        )
        self.assertEqual(ans.returncode, 0)

    def test_rootfs_reads_and_hides_metadata(self):
        self._setup_untar("01-rootfs-metadata-raw.tar")

        cmd = f"""
        set -x;
        cd {STAGING};
        tar cf ../result.tar .
        """
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        with tarfile.open("tests/fixtures/01-rootfs-metadata-mounted.tar") as expect_tar:
            expect_val = _sort_tar_info(map(_tar_info_minimal, expect_tar.getmembers()))
        with tarfile.open("tests/fixtures/result.tar") as actual_tar:
            actual_val = _sort_tar_info(map(_tar_info_minimal, actual_tar.getmembers()))
        self.assertEqual(expect_val, actual_val)

    def test_rootfs_creates_metadata(self):
        self._setup_untar_in_container("01-rootfs-metadata-mounted.tar", rootfs=True)
        ans = c.run_script(f"set -x; cd {STAGING}; find -exec ls -l {{}} \\; 1>&2".encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        cmd = f"""
        cd {STAGING};
        tar cf ../result.tar .
        """
        ok = os.system(cmd)
        self.assertEqual(ok, 0)
        with tarfile.open("tests/fixtures/01-rootfs-metadata-raw.tar") as expect_tar:
            expect_val = _sort_tar_info(map(_tar_info_minimal, expect_tar.getmembers()))
        with tarfile.open("tests/fixtures/result.tar") as actual_tar:
            actual_val = _sort_tar_info(map(_tar_info_minimal, actual_tar.getmembers()))
        self.assertEqual(expect_val, actual_val)


def _sort_tar_info(obj):
    return sorted(obj, key=lambda x: x["name"])


def _tar_info_minimal(obj):
    return {
        "name": obj.name,
        "size": obj.size,
        "mode": obj.mode,
        "type": obj.type,
        "linkname": obj.linkname,
    }


def _tar_info(obj):
    return {
        "mtime": obj.mtime,
        "uid": obj.uid,
        "gid": obj.gid,
        "uname": obj.uname,
        "gname": obj.gname,
        "pax": obj.pax_headers,
        **_tar_info_minimal(obj),
    }
