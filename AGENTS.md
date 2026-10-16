# lumi-praxis-app-updater – Arbeitsregeln

LUMI besteht aus Praxis-App, Patientenportal, API und dem getrennten Releaseziel
der Praxis-App. Fachliche Regeln stehen in `../lumi-api/docs/`; Start, Konfiguration
und Prüfkommandos in der README der jeweiligen Komponente.

## Unveränderliche Fachgrenzen

- Identifizierende Patientendaten und die Zuordnung zu Accounts bleiben lokal in
  der Praxis-App. Portal und API verarbeiten ausschließlich pseudonyme Daten.
- PostgreSQL ist nur über die API erreichbar. Die Praxis-App führt Identdaten
  und API-Daten ausschließlich im Main-Prozess zusammen.
- Ein Tagebucheintrag erzeugt keine Benachrichtigung oder Kontaktanfrage. Nur die
  Patientin oder der Patient löst einen Kontaktwunsch aus und setzt dessen Dringlichkeit.
- Die Praxis darf den Tagebuchverlauf lesen. Die Fragen-Merkliste bleibt privat.
- Keine Tokens, Passwörter, Freitexte oder identifizierenden Daten in technischen Logs.
- Testläufe nutzen isolierte Daten und verändern keine bestehenden Container oder Volumes.

## Gestaltung und Umsetzung

Passende installierte `fluxo-*`-Skills verwenden; Symlinks vor relativen Zugriffen
auflösen. Gemeinsame Designpakete liegen als feste Archive im jeweiligen
Build-Kontext. Produktlaufzeit und CI greifen nie auf die zentrale Bibliothek zu.
Bestehende Stacks erhalten: Electron/React/Forge, Flask/Jinja und FastAPI/PostgreSQL.
Oberflächentexte kurz und aus Nutzersicht formulieren. Keine Entwicklungsanweisungen
in die Oberfläche übernehmen. Neue Fachfunktionen nicht aus historischen Plänen ableiten.

## Git

Vor Änderungen Root und Arbeitsstand prüfen; fremde Änderungen erhalten.
Nach abgeschlossener Arbeit konkrete Conventional Commits mit Umfang vorschlagen.
Commits, Amend und historienändernde Rebase-/Filteroperationen erst nach ausdrücklicher
Zustimmung zu den vorgeschlagenen Commits. Danach erstellte Commits berichten und
gesondert die Push-Freigabe für Remote und Branch einholen. Keine automatische
Veröffentlichung von Installern oder Releases durch einen normalen Push.

Weitere Regeln und Prüfkommandos stehen in der lokalen README.
