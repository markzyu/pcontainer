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
            set -e
            echo "[INITIALIZING TESTS]" >&2
            rm -rf {STAGING}; 
            rm -rf {METADATA}; 
            mkdir -p {STAGING}; 
            cd {STAGING};
            rm -f ../result.tar;
            echo "[INITIALIZED TESTS]" >&2
            """
        )
        self.assertEqual(init_ok, 0)

    def _setup_untar(self, tar_name):
        init_ok = os.system(
            f"""
            echo "[CREATING STAGING FROM TAR]" >&2
            cd {STAGING} && tar xf ../{tar_name};
            if [ $? -ne 0 ]; then
                echo "[ERROR CREATING STAGING FROM TAR]" >&2
                exit $?
            fi
            echo "[CREATED STAGING FROM TAR]" >&2
            """
        )
        self.assertEqual(init_ok, 0)

    def _setup_untar_in_container(self, tar_name, **kwargs):
        ans = c.run_script(
            f"""
            echo "[POCKER] [CREATING STAGING FROM TAR]" >&2
            cd {STAGING} && tar xpf ../{tar_name};
            if [ $? -ne 0 ]; then
                echo "[POCKER] [ERROR CREATING STAGING FROM TAR]" >&2
                exit $?
            fi
            echo "[POCKER] [CREATED STAGING FROM TAR]" >&2
            """.encode(),
            rootfs=True,
            root=True,
            **kwargs,
        )
        self.assertEqual(ans.returncode, 0)

    def _create_tar_from_container(self, dir, tar_name, **kwargs):
        ans = c.run_script(
            f"""
            echo "[POCKER] [CREATING TAR]" >&2
            umask 0077 && cd {dir} && rm -f ../{tar_name} && tar cf ../{tar_name} .
            if [ $? -ne 0 ]; then
                echo "[POCKER] [ERROR CREATING STAGING FROM TAR]" >&2
                exit $?
            fi
            echo "[POCKER] [CREATED TAR]" >&2
            """.encode(),
            rootfs=True,
            **kwargs,
        )
        self.assertEqual(ans.returncode, 0)

    def _create_tar_from_host_os(self, dir, tar_name):
        cmd = f"""
        echo "[ASSERT] [TARRING DIR FOR COMPARISON] {dir}" >&2
        ls -l {STAGING}
        ls -l {METADATA}
        cd {dir} && rm -f ../{tar_name} && tar cf ../{tar_name} .
        if [ $? -ne 0 ]; then
            echo "[ASSERT] [ERROR TARRING DIR FOR COMPARISON]" >&2
            exit $?
        fi
        echo "[ASSERT] [TARRED DIR FOR COMPARISON]" >&2
        """
        ok = os.system(cmd)
        self.assertEqual(ok, 0)

    def compare_tar_with_dir(self, dir, tar, ignore_perms=False):
        if ignore_perms:
            self._create_tar_from_host_os(dir, "result.tar")
        else:
            self._create_tar_from_container(dir, "result.tar")

        tar_info_fn = _tar_info_minimal_no_perms if ignore_perms else _tar_info_minimal

        with tarfile.open(f"tests/fixtures/{tar}") as expect_tar:
            expect_val = _sort_tar_info(map(tar_info_fn, expect_tar.getmembers()))
        with tarfile.open("tests/fixtures/result.tar") as actual_tar:
            actual_val = _sort_tar_info(map(tar_info_fn, actual_tar.getmembers()))
        self.assertEqual(expect_val, actual_val)

    def test_rootfs_creates_metadata(self):
        self._setup_untar_in_container("01-rootfs-metadata-mounted.tar")
        self.compare_tar_with_dir(METADATA, "01-rootfs-metadata-raw.tar", ignore_perms=True)
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
                "/z -> /x\n"
                f"fstatat(/link) = -1 errno = {errno.ENOENT}\n"
                f"fstatat(/a) = -1 errno = {errno.ENOENT}\n"
                f"fstatat(/b) = -1 errno = {errno.ENOENT}\n"
                f"fstatat(/c) = -1 errno = {errno.ENOENT}\n"
                f"fstatat(/y) = -1 errno = {errno.ENOENT}\n"
                f"fstatat(/x) = 0 errno = {errno.ENOENT}\n"
                f"fstatat(/z) = -1 errno = {errno.ENOENT}\n"
            ),
        )
        self.assertEqual(ans.returncode, 0)
    
    def test_chroot_fchown(self):
        os.system(f"ls -l {STAGING}")
        ans = c.run_elf_chroot("tests/fixtures/1a-fchown.out")
        stdout = ans.stdout.decode("utf8")
        print("Actual stdout:")
        print(stdout)
        print()
        self.assertEqual(
            stdout,
            (
                "fstatat(/x): owner = 0 group = 0\n"
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

def _tar_info_minimal_no_perms(obj):
    return {
        "name": obj.name,
        "size": obj.size,
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
