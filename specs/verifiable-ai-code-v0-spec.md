# Verifiable AI Code V0 — Change Linter + LLM Verification Harness

> Historical proposal. The refined implementation contract and explicit delivered/deferred scope are in [SwiftProof V0.2](swiftproof-v0.2-spec.md). This original is preserved for context.

**Status:** Draft v0.1  
**Scope:** MVP simplifié  
**Primary output:** `CONFIDENCE_REPORT.md` + `confidence-report.json`

> Cette V0 remplace l'ambition de vérification complète par un système plus simple : un Change Linter déterministe, un harness contrôlé et un LLM reviewer adversarial.

## 1. Architecture V0

```text
                 git diff
                    │
       ┌────────────┴────────────┐
       ▼                         ▼
 CHANGE LINTER             TEST HARNESS
       │                         │
       └────────────┬────────────┘
                    ▼
              LLM REVIEWER
                    │
                    ▼
          CONFIDENCE_REPORT.md
```

Le LLM est un **investigateur**, pas une autorité. Une hypothèse du modèle n'est pas une preuve : il doit autant que possible la transformer en test ou en observation déterministe.

## 2. Périmètre du MVP

Le MVP MUST : analyser un diff Git ; détecter des signaux de risque ; permettre au reviewer de lire/rechercher le code ; lancer tests, typecheck et build ; générer des tests temporaires adversariaux ; classifier les hypothèses en `REPRODUCED`, `NOT_REPRODUCED`, `UNVERIFIED` ou `DISMISSED` ; produire un rapport Markdown et JSON ; proposer une surface de review humaine ciblée.

Le MVP ne fournit **aucun pourcentage de confiance**. Il expose des faits, des expériences et des incertitudes.

## 3. Change Linter

Le linter compare la baseline au patch et émet des signaux structurés : fichiers et lignes modifiés, dépendances ajoutées, exports/API modifiés, appels réseau, écritures DB, auth/authz, migrations, validations supprimées, changements d'error handling, casts dangereux/type suppressions, TODO/FIXME, hausse de complexité, fonctions importantes sans tests associés et symboles à fort fan-out lorsque l'information est disponible.

Exemple :

```json
{
  "kind": "public_api_change",
  "file": "src/payment/refund.ts",
  "symbol": "Payment.refund",
  "severity": "high",
  "evidence": "exported signature changed"
}
```

Les poids éventuels servent uniquement à distribuer le budget d'investigation ; ils ne sont jamais présentés comme une probabilité de bug.

## 4. Verification Harness

Le reviewer reçoit une API contrôlée plutôt qu'un shell libre :

```text
read_file(path, start?, end?)
get_diff(path?)
search_code(query)
find_references(symbol)
inspect_symbol(symbol)
run_tests(pattern?)
run_test(file)
run_typecheck()
run_build()
create_test(content, metadata)
run_generated_test(test_id)
delete_generated_test(test_id)
```

Le harness MUST valider les chemins, imposer des timeouts, limiter les sorties, journaliser tous les appels, distinguer tests existants et tests générés, conserver les tests reproduisant un problème, masquer les secrets et désactiver le réseau par défaut. Les tests générés vivent dans un espace éphémère séparé du patch.

## 5. Reviewer agentique

Le reviewer reçoit le diff, les signaux du linter, l'intention de la PR/issue si disponible et le harness. Il ne dépend pas du raisonnement privé de l'agent générateur. Son instruction centrale : chercher des contre-exemples concrets, prioriser les risques à fort impact, utiliser les tools pour investiguer et transformer autant que possible chaque inquiétude en test exécutable.

Boucle : `ANALYZE → HYPOTHESIZE → TOOL → OBSERVE → RESOLVE/CONTINUE`. Le budget est configurable, par exemple 20 itérations, 10 tests générés et 10 minutes de runtime de tests.

## 6. Confidence Report V0

Sections obligatoires : **Change Summary**, **Automated Checks**, **Investigation Summary**, **Reproduced Issues**, **Unverified Areas**, **Suggested Human Review**, **Review Surface**.

Exemple :

```text
CHANGE CONFIDENCE REPORT

438 additions / 97 deletions
12 files changed

Automated checks
PASS Typecheck
PASS Existing tests: 847/847
WARN Public API modified

Investigation
12 hypotheses investigated
1 reproduced / 8 not reproduced / 3 unverified

REPRODUCED
Concurrent refunds can exceed captured amount.
Evidence: generated-test-28

UNVERIFIED
Provider timeout after successful remote processing.
Reason: external API unavailable in sandbox.

HUMAN REVIEW
HIGH src/payment/refund.ts:78-104
MEDIUM src/payment/stripe.ts:182-201

Focused review: 46 / 535 changed lines
```

`NOT_REPRODUCED` ne signifie jamais « impossible ». La surface ciblée n'implique pas que le reste du diff est correct.

## 7. Sortie JSON

```json
{
  "version": 1,
  "change": {},
  "linter": {},
  "checks": [],
  "hypotheses": [],
  "evidence": [],
  "reproduced_issues": [],
  "unverified": [],
  "review_targets": [],
  "artifacts": []
}
```

Le Markdown SHOULD être rendu depuis cette représentation structurée.

## 8. CLI

```bash
vac init
vac lint
vac review --base main
vac review main..HEAD
vac report
```

Options : `--max-iterations`, `--format markdown,json`, `--ci`, `--no-network`. Codes de sortie proposés : `0` rapport terminé sans issue bloquante ; `1` issue bloquante reproduite ; `2` review humaine requise ; `3` erreur de configuration ; `4` erreur du harness.

## 9. Configuration minimale

```yaml
version: 1
project:
  language: typescript
commands:
  test: npm test
  typecheck: npm run typecheck
  build: npm run build
reviewer:
  max_iterations: 20
  max_generated_tests: 10
  max_test_runtime_seconds: 600
sandbox:
  network: false
sensitive_paths:
  - src/auth/**
  - src/payments/**
  - migrations/**
```

## 10. Sécurité

Le repository et les tests générés sont du code non fiable. Les exécutions MUST utiliser un environnement éphémère, sans secrets de production, avec réseau désactivé par défaut, limites CPU/RAM/temps, filesystem restreint, audit des commandes et cleanup systématique.

## 11. Intégration CI / PR

`PR → checkout base/candidate → Change Linter → investigation LLM en sandbox → JSON → Markdown → résumé de PR`. La V0 SHOULD publier un seul résumé plutôt qu'une multitude de commentaires inline. Les commentaires inline sont réservés ultérieurement aux problèmes reproduits et zones de review à forte valeur.

## 12. Phases de construction

**Phase 1 — Fondation déterministe :** Git diff, AST TypeScript, Change Linter, runners test/typecheck/build, format Evidence JSON, rapport statique.

**Phase 2 — Reviewer agentique :** tool loop LLM, recherche/références, budget, hypothèses structurées, synthèse du rapport.

**Phase 3 — Tests adversariaux :** génération isolée, exécution, conservation des reproductions, sandbox renforcée.

**Phase 4 — CI :** intégration PR, politiques de blocage, artefacts téléchargeables.

## 13. Critères de succès

Le MVP est utile si des développeurs peuvent comprendre en quelques minutes ce qui a changé et ce qui reste incertain ; si des bugs réels peuvent être reproduits par des tests générés ; si le rapport réduit significativement la surface de review ; si les faux positifs restent acceptables ; et si l'outil ajoute assez peu de friction pour être exécuté sur chaque PR assistée par IA.

## 14. Hypothèse produit à valider

> Un développeur acceptera-t-il de lire beaucoup moins du diff si un système indépendant lui montre les changements risqués, les tests réellement exécutés, les problèmes reproduits, les zones impossibles à vérifier et les quelques régions du code où son jugement est encore nécessaire ?

---

# Annexe — Vision ultérieure

La V0 pourra ensuite évoluer vers des invariants versionnés, règles architecturales, property-based testing, mutation testing, differential testing et Evidence Graph. Ces éléments ne sont pas des prérequis du MVP.
