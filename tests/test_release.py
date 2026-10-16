import hashlib
import importlib.util
import io
from pathlib import Path
import plistlib
import stat
import struct
import tempfile
import unittest
import warnings
import zipfile

spec = importlib.util.spec_from_file_location("verify_release", Path(__file__).parents[1] / "scripts/verify-release.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

VERSION = "0.2.0"
MAC_NAME = f"LUMI Praxis-App-darwin-arm64-{VERSION}.zip"
MAIN = "LUMI Praxis-App.app/Contents/MacOS/lumi-praxis"
PLIST = "LUMI Praxis-App.app/Contents/Info.plist"
NUPKG = f"LUMI_Praxis-{VERSION}-full.nupkg"


def macho(arch="arm64"):
    # Structurally valid header + one command; this fixture is not runnable code.
    return struct.pack("<8I", 0xFEEDFACF, module.CPU[arch], 0, 2, 1, 8, 0, 0) + struct.pack("<II", 1, 8)


def fat_macho():
    slices = [macho("x64"), macho("arm64")]
    return (struct.pack(">II", 0xCAFEBABE, 2)
            + struct.pack(">IIIII", module.CPU["x64"], 0, 48, 40, 0)
            + struct.pack(">IIIII", module.CPU["arm64"], 0, 88, 40, 0) + b"".join(slices))


def pe(machine=0x8664):
    offset, optional_size = 0x80, 240 if machine == 0x8664 else 224
    data = bytearray(offset + 24 + optional_size + 40 + 512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, offset)
    data[offset:offset + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, offset + 4, machine, 1, 0, 0, 0, optional_size, 0x2)
    struct.pack_into("<H", data, offset + 24, 0x20B if machine == 0x8664 else 0x10B)
    return bytes(data)


def mac(root, *, info_updates=None, executable=None, extra=(), mode=stat.S_IFREG | 0o755):
    info = {"CFBundleIdentifier": module.BUNDLE_ID, "CFBundleExecutable": module.EXECUTABLE,
            "CFBundleShortVersionString": VERSION, "CFBundleVersion": VERSION}
    info.update(info_updates or {})
    with zipfile.ZipFile(root / MAC_NAME, "w") as archive:
        archive.writestr(PLIST, plistlib.dumps(info))
        item = zipfile.ZipInfo(MAIN)
        item.create_system = 3
        item.external_attr = mode << 16
        archive.writestr(item, macho() if executable is None else executable)
        for name, content in extra:
            archive.writestr(name, content)


def windows(root, *, package_id=module.PACKAGE_ID, version=VERSION, machine=0x8664, content=None):
    (root / f"LUMI Praxis-App-{VERSION} Setup.exe").write_bytes(pe(0x14C))
    if content is None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("LUMI_Praxis.nuspec", f'<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd"><metadata><id>{package_id}</id><version>{version}</version></metadata></package>')
            archive.writestr("lib/net45/lumi-praxis.exe", pe(machine))
        content = buffer.getvalue()
    (root / NUPKG).write_bytes(content)
    (root / "RELEASES").write_text(f"{hashlib.sha1(content).hexdigest()} {NUPKG} {len(content)}\n")


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def check_mac(self):
        return module.verify(self.root, "macos", "arm64", VERSION)

    def check_windows(self):
        return module.verify(self.root, "windows", "x64", VERSION)

    def test_macos_accepts_matching_real_headers_and_metadata(self):
        mac(self.root)
        self.assertEqual(self.check_mac(), [])

    def test_macos_accepts_matching_universal_binary_slices(self):
        mac(self.root, executable=fat_macho())
        self.assertEqual(self.check_mac(), [])

    def test_macos_rejects_renamed_wrong_architecture(self):
        mac(self.root, executable=macho("x64"))
        self.assertIn("Architektur", self.check_mac()[0])

    def test_macos_rejects_mismatched_native_module(self):
        mac(self.root, extra=[("LUMI Praxis-App.app/Contents/Resources/app.asar.unpacked/sqlite.node", macho("x64"))])
        self.assertIn("Architektur", self.check_mac()[0])

    def test_macos_rejects_version_prefix_and_noncanonical_filename(self):
        mac(self.root)
        for wrong in ("LUMI Praxis-App-darwin-arm64-0.2.00.zip", "Other-darwin-arm64-0.2.0.zip"):
            with self.subTest(wrong=wrong):
                source, target = self.root / MAC_NAME, self.root / wrong
                source.rename(target)
                self.assertTrue(self.check_mac())
                target.rename(source)

    def test_macos_requires_expected_bundle_identity_and_both_versions(self):
        for key in ("CFBundleIdentifier", "CFBundleExecutable", "CFBundleShortVersionString", "CFBundleVersion"):
            with self.subTest(key=key):
                mac(self.root, info_updates={key: "wrong"})
                self.assertTrue(self.check_mac())

    def test_macos_rejects_text_truncated_binary_and_fake_fat_table(self):
        fake = bytearray(fat_macho())
        struct.pack_into(">I", fake, 28, module.CPU["x64"])
        for value in (b"synthetic executable", macho()[:20], bytes(fake)):
            with self.subTest(value=value[:8]):
                mac(self.root, executable=value)
                self.assertTrue(self.check_mac())

    def test_macos_requires_executable_file_instead_of_symlink(self):
        for mode in (stat.S_IFREG | 0o644, stat.S_IFLNK | 0o777):
            with self.subTest(mode=mode):
                mac(self.root, mode=mode)
                self.assertTrue(self.check_mac())

    def test_archives_reject_escape_duplicate_paths_and_bad_zip(self):
        for name in ("../outside", "/outside", "C:/outside", "a\\outside", MAIN):
            with self.subTest(name=name), warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                mac(self.root, extra=[(name, b"bad")])
                self.assertTrue(self.check_mac())
        (self.root / MAC_NAME).write_bytes(b"not a ZIP")
        self.assertTrue(self.check_mac())

    def test_macos_rejects_malformed_plist(self):
        mac(self.root)
        with zipfile.ZipFile(self.root / MAC_NAME, "w") as archive:
            archive.writestr(PLIST, b"malformed")
        self.assertTrue(self.check_mac())

    def test_windows_accepts_x86_bootstrapper_and_x64_application(self):
        windows(self.root)
        self.assertEqual(self.check_windows(), [])

    def test_windows_rejects_nonzip_even_with_matching_manifest(self):
        windows(self.root, content=b"test-package")
        self.assertTrue(self.check_windows())

    def test_windows_rejects_non_pe_setup(self):
        windows(self.root)
        (self.root / f"LUMI Praxis-App-{VERSION} Setup.exe").write_bytes(b"test-setup")
        self.assertTrue(self.check_windows())

    def test_windows_rejects_wrong_app_architecture(self):
        windows(self.root, machine=0x14C)
        self.assertIn("x64", self.check_windows()[0])

    def test_windows_rejects_wrong_id_and_version_in_metadata(self):
        for params in ({"package_id": "Other"}, {"version": "0.2.00"}):
            with self.subTest(params=params):
                windows(self.root, **params)
                self.assertTrue(self.check_windows())

    def test_windows_rejects_corruption_size_and_manifest_escape(self):
        windows(self.root)
        content = (self.root / NUPKG).read_bytes()
        (self.root / NUPKG).write_bytes(content[:-1] + bytes([content[-1] ^ 1]))
        self.assertIn("Paketprüfsumme", self.check_windows()[0])
        (self.root / NUPKG).write_bytes(content[:-10])
        self.assertIn("Paketgröße", self.check_windows()[0])
        (self.root / "RELEASES").write_text(f"{'0' * 40} ../{NUPKG} 12\n")
        self.assertTrue(self.check_windows())

    def test_windows_requires_matching_setup_filename_and_single_manifest_entry(self):
        windows(self.root)
        setup = self.root / f"LUMI Praxis-App-{VERSION} Setup.exe"
        setup.rename(self.root / "LUMI Praxis-App-0.2.00 Setup.exe")
        self.assertTrue(self.check_windows())
        windows(self.root)
        manifest = self.root / "RELEASES"
        manifest.write_text(manifest.read_text() * 2)
        self.assertTrue(self.check_windows())

    def test_windows_rejects_symlink_package(self):
        windows(self.root)
        target = self.root / "source.nupkg"
        (self.root / NUPKG).rename(target)
        (self.root / NUPKG).symlink_to(target)
        self.assertTrue(self.check_windows())

    def test_rejects_invalid_versions_and_targets(self):
        for version in ("00.2.0", "0.2.00", "1٢.2.0", "0.2.0-rc.1", "0.2.0+build", "0.2.0\n", "../0.2.0"):
            with self.subTest(version=version):
                self.assertTrue(module.verify(self.root, "macos", "arm64", version))
        self.assertTrue(module.verify(self.root, "windows", "arm64", VERSION))
        self.assertTrue(module.verify(self.root, "linux", "x64", VERSION))
        self.assertTrue(module.verify(self.root, "macos", "other", VERSION))


if __name__ == "__main__":
    unittest.main()
