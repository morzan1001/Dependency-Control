# Phase D: Konsolidierung der Fake-Mongo-Test-Fixtures

**Status:** Geplant, nicht begonnen
**Erstellt:** 2026-05-13
**Erwartete Ersparnis:** ~400 LoC + zentraler Test-Infrastruktur-Wartungspunkt
**Risiko:** Hoch — kann subtile Test-Verhaltensänderungen in mehreren Suites auslösen
**Geschätzte Dauer:** 2–3 fokussierte Stunden

## Problem

Drei `tests/**/conftest.py` definieren je eine eigene `async def db()`-Fixture, jede mit eigener Fake-Mongo-Implementierung:

| Datei | LoC | Was sie enthält |
|---|---|---|
| `backend/tests/unit/conftest.py` | 409 | Vollwertige Fake-Mongo mit `_match_doc`, `_resolve_field`, `_run_pipeline` (≈ 380 Zeilen Pipeline-Reimplementierung — `$match`, `$group`, `$sort`, `$limit`, `$skip`, `$lookup`, `$facet`, `$addFields`) |
| `backend/tests/integration/conftest.py` | 793 | Eigene Fake-Mongo mit `_fake_match_doc`, `_fake_match`, `_fake_group`, `_resolve_dotted` — partiell überlappender Operator-Support |
| `backend/tests/services/analytics/conftest.py` | 15 | Minimal, importiert vermutlich von unit/conftest |
| `backend/tests/mocks/mongodb.py` | 77 | Nur ein `AsyncMock`-Builder (`create_mock_collection`, `create_mock_db`) — KEIN Fake, sondern Mock-Wrapper |

Beide Fakes haben sich unabhängig entwickelt. `_resolve_field` ist in beiden Files definiert (`unit/conftest.py:59` und `integration/conftest.py:141`) — wahrscheinlich mit subtilen Unterschieden.

Die zwei Fakes stellen **dieselbe Mongo-API nach** (Collection, AsyncIteratorCursor, aggregate, find, find_one, insert_many, update_one, etc.), aber unabhängig. Bugs müssen zweimal gefixt werden, Operator-Support driftet auseinander.

## Ziel

Eine **zentrale Fake-Mongo-Implementierung** in `backend/tests/mocks/fake_mongo.py`, die beide Konsumenten bedient. Bestehende Tests laufen unverändert weiter. `mocks/mongodb.py` bleibt für reine Mock-Cases (keine Fake-Datenhaltung).

## Vorbedingungen

- Phase A+B+C dieser Session sind committed
- `pytest` läuft sauber: `cd backend && python -m pytest tests/ --ignore=tests/integration --ignore=tests/test_chat_rate_limiter.py --ignore=tests/test_main.py --ignore=tests/test_chat_repository.py --ignore=tests/unit/test_crypto_policy_seeder.py` → 2645 passed
- Branch `phase-d-fixture-consolidation` aus aktuellem `main`

## Strategie: Inkrementell, mit Verhaltens-Probe

**Anti-Pattern:** "Beide Fakes parsen, vereinheitlichen, alle Tests anpassen, hoffen dass es passt." Risiko: Wochen Debugging.

**Pattern:** Behavioral-Probe-First, **dann** Konsolidieren.

### Schritt 1 — Verhaltens-Probe (kein Refactor)

Skript schreiben (`backend/tests/mocks/_compare_fakes.py`, nur lokal, nicht committen), das beide Fakes mit identischer Sequenz von Operationen füttert und Output diff'ed:

```python
# Pseudocode
SCENARIOS = [
    # Operatoren
    ("$match with $regex case-insensitive", ...),
    ("$match with $in over numeric range", ...),
    ("$match with $exists=false", ...),
    ("$group with $sum + $count", ...),
    ("$sort multi-field", ...),
    ("$lookup with sub-pipeline", ...),
    ("$facet with two branches", ...),
    ("$addFields with $cond", ...),
    ("nested $project", ...),
    # Edge cases
    ("empty collection", ...),
    ("missing field on doc", ...),
    ("null vs absent", ...),
    ("very large skip+limit", ...),
]
```

Pro Szenario: beide Fakes ausführen, JSON-Output vergleichen, Diff loggen. Erwartetes Ergebnis: **3–10 Verhaltensunterschiede**. Diese sind die Risiko-Hotspots.

### Schritt 2 — Behavioral-Spec festschreiben

Aus Schritt 1: pro Operator definieren, welches Verhalten das "richtige" ist (typischerweise das, das näher an echtem MongoDB liegt — siehe `mongomock` als Referenz). Dokumentieren in `tests/mocks/fake_mongo_README.md`.

Für jeden Unterschied entscheiden:
- (a) Vereinheitlichen auf Variante X, betroffene Tests prüfen / anpassen
- (b) Optionaler Schalter (z. B. `FakeMongo(strict_null_semantics=True)`)
- (c) Kein gemeinsamer Code — Variante separat halten

### Schritt 3 — Zentrale Implementierung schreiben

`backend/tests/mocks/fake_mongo.py` als sauberes Modul:

```python
class FakeCollection:
    def __init__(self, docs: list[dict] | None = None): ...
    async def find_one(self, filter): ...
    async def find(self, filter): ...
    async def insert_many(self, docs): ...
    async def update_one(self, filter, update): ...
    async def aggregate(self, pipeline): ...  # delegiert an _run_pipeline
    # ... rest of Motor-API surface

class FakeDatabase:
    def __init__(self): ...
    def __getitem__(self, name) -> FakeCollection: ...
    @property
    def projects(self) -> FakeCollection: ...  # für ``db.projects`` style
    # ...

def _run_pipeline(docs, pipeline): ...  # die echte Pipeline-Implementierung
def _match_doc(doc, condition): ...
def _resolve_field(doc, expr): ...
```

**Wichtig:** Public-API der `db`-Fixture für Konsumenten bleibt **identisch**. `db.projects._docs[...]`, `await db["scans"].insert_many(...)`, etc. — alles unverändert.

### Schritt 4 — `unit/conftest.py` migrieren

```python
# tests/unit/conftest.py
import pytest_asyncio
from tests.mocks.fake_mongo import FakeDatabase

@pytest_asyncio.fixture
async def db():
    return FakeDatabase()
```

Alles andere aus `unit/conftest.py:1-409`, das auf den lokalen Fake zugriff, raus. Die Datei sollte am Ende ~30 Zeilen sein (Fixture-Definition + ggf. Test-Helper, die nicht zur Mongo-Logik gehören).

Verifizieren:
```bash
cd backend && python -m pytest tests/unit/ --tb=short -q 2>&1 | tail -15
```

Erwartung: **alle Unit-Tests grün**. Wenn nicht: jeweiliges Verhalten in `fake_mongo.py` angleichen, NICHT die Tests ändern.

### Schritt 5 — `integration/conftest.py` migrieren

Selbes Muster. Wenn `integration/` zusätzliche DB-Setup-Helfer hat (z. B. Seeding-Fixtures, Auth-Setup, etc.), die bleiben in `integration/conftest.py`. Nur die Fake-Mongo-Logik raus.

Verifizieren:
```bash
cd backend && python -m pytest tests/integration/ --tb=short -q 2>&1 | tail -15
```

Bei integration ist Vorsicht geboten, weil dort echte Service-Calls hinzukommen — viele Tests setzen erweiterte Operator-Pfade voraus (`$lookup` mit nested pipelines etc.).

### Schritt 6 — `services/analytics/conftest.py` migrieren

Mini-File. Sollte schnell gehen — vermutlich nur 5–10 Zeilen Anpassung.

### Schritt 7 — Aufräumen

- `mocks/_compare_fakes.py` löschen (war nur lokales Hilfsskript)
- `mocks/fake_mongo_README.md` als Behavioral-Spec behalten — wichtig für künftige Maintainer
- Imports prüfen: kein Test importiert `_resolve_field` / `_run_pipeline` direkt aus conftest

### Schritt 8 — Voll-Lauf

```bash
cd backend && python -m pytest tests/ --ignore=tests/test_chat_rate_limiter.py --ignore=tests/test_main.py --ignore=tests/test_chat_repository.py --ignore=tests/unit/test_crypto_policy_seeder.py --tb=short -q 2>&1 | tail -10
```

Erwartung: 2645 passed wie vor der Session.

## Risiko-Mitigation

1. **Branch + früh-committen.** Jeder Schritt = ein Commit. Bei Fehlschlag in Schritt N: `git revert` und neu ansetzen.
2. **Behavioral-Probe (Schritt 1) ist nicht optional.** Sie kostet 20 Minuten und spart Stunden Debugging.
3. **Subtile Bug-Kategorien zum Testen:**
   - `$lookup` mit `let` + `$expr` — typische Stolperfalle bei Custom-Fakes
   - `$facet` mit unterschiedlich shaped sub-pipelines
   - `null` vs. missing field bei `$match` (Mongo behandelt das nicht-trivial)
   - `$sort` mit gemischten Typen
4. **Tests, die Mock-Internals verwenden** (z. B. `db.projects._docs["x"] = {...}` für Seeding): API beibehalten oder eine explizite `seed(name, docs)`-Methode anbieten. Erstmal API beibehalten, später optional aufräumen.
5. **mongomock als Notfall-Plan:** Wenn die Konsolidierung zu kompliziert wird, ist ein Wechsel zu [`mongomock`](https://github.com/mongomock/mongomock) (PyPI-Package, viel breiterer Operator-Support) eine valide Alternative. Trade-off: externe Dependency, evtl. Verhaltens-Drift gegenüber echtem Motor-API. Aber: weniger Wartung als Eigen-Fake. **Vor Schritt 3 entscheiden.**

## Definition of Done

- [ ] `backend/tests/mocks/fake_mongo.py` existiert mit dokumentierter Public-API
- [ ] `backend/tests/mocks/fake_mongo_README.md` listet alle unterstützten Operatoren + bekannte Abweichungen vom echten MongoDB
- [ ] `tests/unit/conftest.py` ≤ 50 Zeilen
- [ ] `tests/integration/conftest.py` ≥ 100 Zeilen weniger als heute (793 LoC), Fake-Logik komplett entfernt
- [ ] `pytest tests/` mit denselben 2645 passing Tests wie aktuell
- [ ] PR-Beschreibung referenziert behavioral-Probe-Ergebnis aus Schritt 1
- [ ] Folge-Issue dokumentiert Tests, die durch echte Behavior-Vereinheitlichung "schärfer" geworden sind (z. B. solche, die vorher implizit auf einen Bug einer der zwei Fakes setzten)

## Anschluss-Aufgaben (Out-of-Scope für Phase D)

- **Over-mocked Tests in `test_audit_history_service.py`**: 3 Tests durch einen echten Integrationstest gegen die konsolidierte Fake-Mongo ersetzen. Erst nach Phase D angehen, weil sie genau diese Infrastruktur brauchen.
- **Eventuell mongomock-Migration** wenn der Eigen-Fake auch nach Konsolidierung mehr Operator-Lücken als gewünscht hat.

## Anti-Goals (was NICHT in Phase D gehört)

- Keine Tests in der Domäne verändern (außer wenn ein Test auf einem nachweisbaren Fake-Bug aufbaute — dann eigener Commit)
- Kein Wechsel der Test-Framework-Konventionen (pytest-asyncio, fixtures)
- Kein gleichzeitiger Switch von Motor → AsyncIOMotorClient-API (anderes Refactoring)
- Kein Auf-Räumen der over-mocked Tests in derselben Session (eigene Folge-Session)
