from common import METADATA, STAGING
import common as c
import errno
import os
import subprocess
import tarfile
import time
import unittest as t


class TestRootFs(t.TestCase):
    maxDiff = 8192

    def setUp(self):
        init_ok = os.system(
            f"""
            pwd >&2;
            rm -rf {STAGING}; 
            rm -rf {METADATA}; 
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

    def compare_tar_with_dir(self, dir, tar):
        cmd = f"""
        cd {dir};
        rm ../result.tar;
        tar cf ../result.tar .
        """
        ok = os.system(cmd)
        self.assertEqual(ok, 0)
        with tarfile.open(f"tests/fixtures/{tar}") as expect_tar:
            expect_val = _sort_tar_info(map(_tar_info_minimal, expect_tar.getmembers()))
        with tarfile.open("tests/fixtures/result.tar") as actual_tar:
            actual_val = _sort_tar_info(map(_tar_info_minimal, actual_tar.getmembers()))
        self.assertEqual(expect_val, actual_val)

    def test_rootfs_creates_metadata(self):
        self._setup_untar_in_container("01-rootfs-metadata-mounted.tar", rootfs=True)
        self.compare_tar_with_dir(METADATA, "01-rootfs-metadata-raw.tar")
        self.compare_tar_with_dir(STAGING, "01-rootfs-metadata-mounted.tar")

    def test_rm_rf_after_rootfs_creates_metadata(self):
        """
        See #20 for details on why this is necessary
        """
        self.test_rootfs_creates_metadata()

        cmd = f"""
        set -x;
        rm -rf {STAGING};
        """
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertFalse(os.path.exists(STAGING))
        self.assertFalse(os.path.exists(METADATA + "/rootfs"))

    def test_rmdir_deletes_untracked_metadata_files(self):
        """
        Delete the metadata of direct children of a folder, even
        if that metadata was created by mistake...

        (This is useful for now, but should be deprecated once we
        cover all unlink/rmdir syscalls)
        """
        self.test_rootfs_creates_metadata()
        timestamp = int(time.time())
        os.system(f"touch {STAGING}/.blahblahblah-{timestamp}")

        cmd = f"""
        set -x;
        rm -rf {STAGING};
        """
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertFalse(os.path.exists(STAGING))
        self.assertFalse(os.path.exists(METADATA + "/rootfs"))
    
    def test_chroot_symlinks(self):
        os.system(f"ls -l {STAGING}")
        ans = c.run_elf_chroot("tests/fixtures/05-symlinks.out")
        stdout = ans.stdout.decode("utf8")
        print("Actual stdout:")
        print(stdout)
        print()
        self.assertEqual(
            stdout,
            (
                "created symlinks\n"
                "/link -> /link\n"
                "/a -> /c\n"
                "/y -> /x\n"
                f"readlink(/x) = -1 errno = {errno.EINVAL} \n"
                f"open(/link) = -1 errno = {errno.ELOOP}\n"
                f"open(/a) = -1 errno = {errno.ELOOP}\n"
                f"open(/y) = 0 errno = {errno.ELOOP}\n"
                f"open(/x) = 0 errno = {errno.ELOOP}\n"
                f"access(/link) = -1 errno = {errno.ENOENT}\n"
                f"access(/a) = -1 errno = {errno.ENOENT}\n"
                f"access(/b) = -1 errno = {errno.ENOENT}\n"
                f"access(/c) = -1 errno = {errno.ENOENT}\n"
                f"access(/y) = -1 errno = {errno.ENOENT}\n"
                f"access(/x) = 0 errno = {errno.ENOENT}\n"
            ),
        )
        self.assertEqual(ans.returncode, 0)


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
