#!/usr/bin/env python3
"""Check LUMI Forge artifacts locally; never extract, execute, sign or upload them."""

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import struct
import sys
import xml.etree.ElementTree as ET
import zipfile
import zlib

# Contract from lumi-praxis-app/package.json and forge.config.js (Forge 8).
PRODUCT = "LUMI Praxis-App"
BUNDLE_ID = "io.fluxo.lumi.praxis"
EXECUTABLE = "lumi-praxis"
PACKAGE_ID = "LUMI_Praxis"
CPU = {"x64": 0x01000007, "arm64": 0x0100000C}
THIN = {b"\xcf\xfa\xed\xfe": "<", b"\xfe\xed\xfa\xcf": ">"}
FAT = {b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
       b"\xca\xfe\xba\xbf": (">", True), b"\xbf\xba\xfe\xca": ("<", True)}


class InvalidArtifact(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidArtifact(message)


def read_at(stream, offset, size):
    stream.seek(offset)
    data = stream.read(size)
    require(len(data) == size, "Binärdatei ist abgeschnitten.")
    return data


def mach_architectures(stream, size, executable=False):
    """Inspect thin/fat Mach-O headers, including the headers of all fat slices."""
    def thin(offset, length):
        header = read_at(stream, offset, 32)
        require(header[:4] in THIN, "Ungültiger 64-Bit-Mach-O-Header.")
        _, cpu, _, kind, count, commands, _, _ = struct.unpack(THIN[header[:4]] + "8I", header)
        require(0 < count <= commands // 8 and 32 + commands <= length,
                "Ungültige Mach-O-Ladebefehlsgröße.")
        require(not executable or kind == 2, "Mach-O ist keine ausführbare App.")
        return cpu

    magic = read_at(stream, 0, 4)
    if magic in THIN:
        return {thin(0, size)}
    require(magic in FAT, "Datei ist kein unterstütztes Mach-O-Binary.")
    order, wide = FAT[magic]
    count = struct.unpack(order + "I", read_at(stream, 4, 4))[0]
    require(0 < count <= 16, "Ungültige Mach-O-Architekturtabelle.")
    record_size = 32 if wide else 20
    end = 8 + count * record_size
    records = read_at(stream, 8, count * record_size)
    architectures, ranges = set(), []
    for index in range(count):
        record = records[index * record_size:(index + 1) * record_size]
        values = struct.unpack(order + ("IIQQII" if wide else "IIIII"), record)
        cpu, _, offset, length, alignment = values[:5]
        require(offset >= end and length >= 32 and offset + length <= size and alignment <= 31
                and offset % (1 << alignment) == 0, "Ungültige Mach-O-Slice.")
        require(not any(offset < stop and offset + length > start for start, stop in ranges),
                "Überlappende Mach-O-Slices.")
        require(cpu not in architectures and thin(offset, length) == cpu,
                "Mach-O-Architekturtabelle widerspricht dem Binary.")
        architectures.add(cpu)
        ranges.append((offset, offset + length))
    return architectures


def pe_machine(stream, size):
    """Read DOS/PE/COFF and optional headers; does not verify executable behavior."""
    require(read_at(stream, 0, 2) == b"MZ", "Datei besitzt keinen DOS/PE-Header.")
    offset = struct.unpack("<I", read_at(stream, 0x3C, 4))[0]
    require(0x40 <= offset <= size - 24, "Ungültiger PE-Headeroffset.")
    header = read_at(stream, offset, 24)
    require(header[:4] == b"PE\0\0", "Ungültige PE-Signatur.")
    machine, sections, _, _, _, optional_size, flags = struct.unpack("<HHIIIHH", header[4:])
    require(0 < sections <= 96 and flags & 0x2 and not flags & 0x2000,
            "PE-Datei ist keine ausführbare Anwendung.")
    expected = {0x14C: (0x10B, 96), 0x8664: (0x20B, 112)}
    require(machine in expected, "Nicht unterstützte PE-Architektur.")
    magic, minimum = expected[machine]
    require(optional_size >= minimum and offset + 24 + optional_size + sections * 40 <= size,
            "Unvollständige PE-Header.")
    require(struct.unpack("<H", read_at(stream, offset + 24, 2))[0] == magic,
            "PE-Architektur und optionaler Header widersprechen sich.")
    return machine


def archive_entries(archive, windows=False):
    entries = {}
    for item in archive.infolist():
        name = item.filename
        parts = PurePosixPath(name).parts
        require(name and not name.startswith("/") and "\\" not in name and ":" not in name
                and ".." not in parts and "." not in name.split("/") and "//" not in name,
                "ZIP enthält einen unzulässigen Dateipfad.")
        key = name.casefold() if windows else name
        require(key not in entries, "ZIP enthält doppelte Dateipfade.")
        require(not windows or not stat.S_ISLNK(item.external_attr >> 16),
                "Windows-ZIP enthält einen symbolischen Link.")
        entries[key] = item
    require(archive.testzip() is None, "ZIP enthält beschädigte Dateien.")
    return entries


def metadata(archive, name, limit=1024 * 1024):
    item = archive.getinfo(name)
    require(not item.is_dir() and not stat.S_ISLNK(item.external_attr >> 16)
            and 0 < item.file_size <= limit, "Ungültige Paketmetadaten.")
    return archive.read(item)


def verify_macos(package, arch, version):
    with zipfile.ZipFile(package) as archive:
        entries = archive_entries(archive)
        root = f"{PRODUCT}.app/"
        plists = [name for name in entries if re.fullmatch(r"[^/]+\.app/Contents/Info\.plist", name)]
        require(plists == [root + "Contents/Info.plist"], "Genau ein LUMI-App-Bundle ist erforderlich.")
        info = plistlib.loads(metadata(archive, plists[0]))
        require(isinstance(info, dict) and info.get("CFBundleIdentifier") == BUNDLE_ID,
                "macOS-Bundle-ID stimmt nicht.")
        require(info.get("CFBundleShortVersionString") == version and info.get("CFBundleVersion") == version,
                "macOS-Bundleversion stimmt nicht.")
        require(info.get("CFBundleExecutable") == EXECUTABLE, "macOS-App-Executable stimmt nicht.")
        main = root + f"Contents/MacOS/{EXECUTABLE}"
        require(main in entries, "macOS-App-Executable fehlt.")
        require(stat.S_ISREG(entries[main].external_attr >> 16)
                and entries[main].external_attr >> 16 & 0o111, "macOS-App-Executable ist nicht ausführbar.")
        # Check every unpacked Mach-O, including Electron helpers and native .node modules.
        # Symlinks in frameworks are retained; no archive member is extracted.
        for name, item in entries.items():
            if not name.startswith(root) or item.is_dir() or stat.S_ISLNK(item.external_attr >> 16):
                continue
            with archive.open(item) as stream:
                magic = stream.read(4)
                if magic in THIN or magic in FAT or magic in (b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce") or name == main or name.endswith((".node", ".dylib")):
                    require(CPU[arch] in mach_architectures(stream, item.file_size, executable=name == main),
                            f"macOS-Architektur stimmt nicht: {name}")


def verify_nupkg(package, version):
    with zipfile.ZipFile(package) as archive:
        entries = archive_entries(archive, windows=True)
        nuspecs = [item.filename for item in entries.values() if item.filename.lower().endswith(".nuspec")]
        require(nuspecs == [f"{PACKAGE_ID}.nuspec"], "NuGet-Paketmetadaten fehlen oder sind nicht eindeutig.")
        xml = metadata(archive, nuspecs[0])
        require(b"<!DOCTYPE" not in xml.upper() and b"<!ENTITY" not in xml.upper(), "NuGet-Metadaten enthalten eine DTD.")
        info = ET.fromstring(xml)
        require(info.findtext("{*}metadata/{*}id") == PACKAGE_ID, "NuGet-Paket-ID stimmt nicht.")
        require(info.findtext("{*}metadata/{*}version") == version, "NuGet-Paketversion stimmt nicht.")
        main = f"lib/net45/{EXECUTABLE}.exe"
        require(main in entries, "Windows-App-Executable fehlt im Paket.")
        item = entries[main]
        with archive.open(item) as stream:
            require(pe_machine(stream, item.file_size) == 0x8664, "Windows-App ist nicht x64.")


def verify_windows(files, version):
    manifests = [p for p in files if p.name == "RELEASES" and p.is_file() and not p.is_symlink()]
    require(len(manifests) == 1, "Genau eine RELEASES-Datei ist erforderlich.")
    manifest = manifests[0]
    setup = manifest.parent / f"{PRODUCT}-{version} Setup.exe"
    require(setup.is_file() and not setup.is_symlink(), "Windows-Setup für diese Version fehlt.")
    with setup.open("rb") as stream:
        pe_machine(stream, setup.stat().st_size)  # Squirrel bootstrapper may be x86 for an x64 app.
    expected = f"{PACKAGE_ID}-{version}-full.nupkg"
    lines = manifest.read_text(encoding="utf-8-sig").splitlines()
    require(len(lines) == 1, "RELEASES muss genau das vollständige Paket dieses Builds enthalten.")
    parts = lines[0].split()
    require(len(parts) == 3 and re.fullmatch(r"[0-9a-fA-F]{40}", parts[0])
            and parts[2].isdigit(), "Ungültiger Eintrag in RELEASES.")
    digest, name, size = parts
    require(name == expected, "RELEASES-Paketname oder -version stimmt nicht.")
    package = manifest.parent / name
    require(package.is_file() and not package.is_symlink(), "Vollständiges Windows-Paket fehlt.")
    require(package.stat().st_size == int(size), "Paketgröße stimmt nicht.")
    with package.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha1").hexdigest() == digest.lower(), "Paketprüfsumme stimmt nicht.")
    verify_nupkg(package, version)


def verify(directory: Path, platform: str, arch: str, version: str) -> list[str]:
    try:
        require(directory.is_dir(), "Artefaktordner fehlt.")
        # This repository publishes stable releases only (Forge prerelease: false).
        require(re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version),
                "Eine stabile Versionsnummer X.Y.Z ohne führende Nullen ist erforderlich.")
        require(arch in CPU, "Unbekannte Architektur.")
        files = list(directory.rglob("*"))
        if platform == "windows":
            require(arch == "x64", "Windows wird nur für x64 ausgeliefert.")
            verify_windows(files, version)
        elif platform == "macos":
            expected = f"{PRODUCT}-darwin-{arch}-{version}.zip"
            candidates = [p for p in files if p.name == expected and p.is_file() and not p.is_symlink()]
            require(len(candidates) == 1, f"Genau ein macOS-ZIP namens {expected} ist erforderlich.")
            verify_macos(candidates[0], arch, version)
        else:
            raise InvalidArtifact("Unbekannte Plattform.")
    except InvalidArtifact as error:
        return [str(error)]
    except (OSError, UnicodeError, KeyError, ValueError, struct.error, EOFError,
            zipfile.BadZipFile, zlib.error, RuntimeError, NotImplementedError, ET.ParseError, plistlib.InvalidFileException):
        return ["Artefakte oder Paketmetadaten sind beschädigt oder nicht lesbar."]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--platform", choices=["windows", "macos"], required=True)
    parser.add_argument("--arch", choices=["x64", "arm64"], required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    errors = verify(args.directory, args.platform, args.arch, args.version)
    for error in errors:
        print(error, file=sys.stderr)
    if not errors:
        print("Artefaktstruktur, Metadaten und App-Architektur geprüft. Signatur und Installation nicht geprüft.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
