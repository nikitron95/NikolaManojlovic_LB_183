# Applikationssicherheit

## Einleitung

Diese Dokumentation präsentiert die Entwicklung von sicheren Web-Applikationen, beginnend mit der Erkennung und Abwehr aktueller Bedrohungen, über das Aufspüren und Schließen von Sicherheitslücken, bis hin zur Umsetzung robuster Authentifizierungs- und Autorisierungsmechanismen. Zudem werden die Integration von Sicherheitsaspekten in den Software-Lebenszyklus und die Implementierung effektiver Auditing- und Logging-Verfahren erläutert.

## Aktuelle Bedrohungen

**Broken Authentication**

Wenn Authentifizierungsverfahren fehlerhaft implementiert sind, können Angreifer Identitäten übernehmen.

Gegenmassnahmen

* Multi-Faktor-Authentifizierung
* Sichere Management von Sessions

**Sensitive Data Exposure**

Sensible Daten können durch unzureichende Verschlüsselung oder Sicherheitsprotokolle kompromittiert werden.

Gegenmassnahmen

* Verwendung von starken Verschlüsselungsstandards
* Sicheren Übertragungsprotokollens

**Security Misconfiguration**

Bezieht sich auf Fehler in der Softwarekonfiguration oder beim Betriebssystem, Netzwerk-Diensten und Plattformen

Gegenmassnahmen

* Regelmäßige Sicherheitsaudits durchgeführen
* Konfigurationsmanagement-Tools

**XML External Entities (XXE)**

Sind Sicherheitsanfälligkeiten beim Parsen von XML-Dokumenten. Angreifer könnten schädliche Inhalte in XML-Dokumente einschleusen, um vertrauliche Daten auszulesen, Remote-Dienste zu beeinträchtigen oder den Server zu überlasten

Gegenmassnahmen

* Sichere Parsing-Libraries verwenden
* Alle Eingaben die in XML-Dokumente eingehen, sorgfältig validieren


## Sicherheitslücken und ihre Ursachen

ff

## Mechanismen für die Authentifizierung und Autorisierung

ss

## Sicherheitsaspekte bei der Systementwicklung

ss

## Auditing und Logging: Schlüsselstrategien für Auswertungen und Alarme

xx
