# LUMI Praxis-App – Updates

Dieses Repository enthält den Releasevertrag und die veröffentlichten Installer
der LUMI-Praxis-App. Quellcode und Builds liegen im
[App-Repository](https://github.com/fluxo-io/lumi-praxisApp).

## Ziele

| Plattform | Architektur | Zusammengehörige Artefakte |
|---|---|---|
| Windows | x64 | Squirrel-Setup `.exe`, vollständiges `.nupkg`, `RELEASES` |
| macOS | arm64 | signiertes, notarisiertes App-ZIP für arm64 |
| macOS | x64 | signiertes, notarisiertes App-ZIP für x64 |

GitHub-Releases für den öffentlichen Electron-Updatefeed müssen öffentlich
erreichbar sein. Der Quellcode kann unabhängig davon privat bleiben. Eine
Änderung der Repository-Sichtbarkeit ist eine eigene Freigabe.

Der Feed folgt `https://update.electronjs.org/fluxo-io/lumi-praxisApp-updater/PLATFORM-ARCH/VERSION`.
Die App verwendet den nativen Electron-Updater. Eine Prüfung lädt ein gefundenes
Update bereits herunter; die Installation erfolgt nach einer Nutzerentscheidung
oder beim nächsten regulären App-Start. Bei nicht unterstützter Umgebung bleibt
die Updatefunktion mit verständlichem Status deaktiviert.

## Veröffentlichung

1. App-Version im Quellrepository setzen und die dort dokumentierten Prüfungen ausführen.
2. Windows x64 und beide macOS-Architekturen mit den passenden Signing-Zertifikaten bauen.
3. Lokale Dateien mit `scripts/verify-release.py` prüfen.
4. Nach Freigabe den manuellen Releaseablauf im Quellrepository ausführen.
5. Signatur, Notarisierung und ein Update von einer installierten älteren Version
   auf jeder Zielplattform prüfen. Erst danach ist der Updatepfad nachgewiesen.

Ein normaler Git-Push erzeugt oder veröffentlicht keinen Release. Tokens und
Signing-Zertifikate gehören ausschließlich in die CI-Secrets des Quellrepositorys.
Ein dort eingesetztes GitHub-Token benötigt Schreibrechte auf dieses Releaseziel;
das automatische `GITHUB_TOKEN` eines anderen Repositories genügt dafür nicht.

## Artefakte prüfen

```sh
python3 scripts/verify-release.py --directory /pfad/zu/windows --platform windows --arch x64 --version 0.2.0
python3 scripts/verify-release.py --directory /pfad/zu/macos-arm64 --platform macos --arch arm64 --version 0.2.0
python3 scripts/verify-release.py --directory /pfad/zu/macos-x64 --platform macos --arch x64 --version 0.2.0
python3 -m unittest discover -s tests -v
```

Der Prüfer benötigt Python 3.11 oder neuer und ausschließlich die Standardbibliothek.
Er folgt den Namen und Einstellungen aus `package.json` und `forge.config.js` der
Praxis-App. Aktuell werden stabile Versionen `X.Y.Z` ohne führende Nullen,
Buildmetadaten oder Vorabkennzeichen veröffentlicht. Bei Änderungen am
Produktnamen, Bundle-Identifier, Executable oder Forge-Maker muss dieser Vertrag
mit angepasst werden.

| Ziel | Exakte Artefaktnamen für Version `0.2.0` |
|---|---|
| macOS arm64 | `LUMI Praxis-App-darwin-arm64-0.2.0.zip` |
| macOS x64 | `LUMI Praxis-App-darwin-x64-0.2.0.zip` |
| Windows x64 | `LUMI Praxis-App-0.2.0 Setup.exe`, `LUMI_Praxis-0.2.0-full.nupkg`, `RELEASES` |

Für macOS prüft das Skript ZIP-Lesbarkeit und CRC, eindeutige Archivpfade,
das oberste App-Bundle, `CFBundleIdentifier`, beide Versionsfelder und
`CFBundleExecutable` in der `Info.plist`. Das Hauptprogramm muss als ausführbare
Datei enthalten sein. Seine Mach-O-Header sowie die erkennbaren, entpackten
Mach-O-Binaries einschließlich Electron-Helpern und nativen `.node`-Modulen müssen
die gewählte Architektur enthalten. Universal-Binaries werden anhand ihrer
Slice-Tabelle und der tatsächlichen Slice-Header geprüft.

Für Windows müssen Setup und Manifest nebeneinander liegen. Der aktuelle
Forge-Vertrag erzeugt genau ein vollständiges Paket ohne Delta-Updates; `RELEASES`
muss genau dieses Paket mit passender Größe und SHA-1 benennen. Das Paket muss
ein lesbares ZIP mit korrekter CRC, `LUMI_Praxis.nuspec`, passender Paket-ID und
Version sein. Die enthaltene `lib/net45/lumi-praxis.exe` wird anhand ihrer
DOS-/PE-/COFF-Header auf x64 geprüft. Der Squirrel-Setup-Bootstrapper darf selbst
x86 oder x64 sein; sein Header bestimmt nicht die App-Architektur.

Der Prüfer extrahiert und startet keine Dateien. Die Headerprüfung bestätigt
keine vollständige Lauffähigkeit, eingebettete Setup-Version oder Übereinstimmung
des Setup-Payloads mit dem separaten Paket. Sie prüft keine Signaturen,
Notarisierung oder Vertrauenskette und ersetzt weder einen nativen Starttest noch
ein installiertes Update auf jedem Zielsystem. Insbesondere kann auch ein
unsignierter lokaler Mac-Build diese Strukturprüfung bestehen.

Die binären Formate orientieren sich an Apples
[Mach-O-Headern](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
und Microsofts [PE-Spezifikation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
