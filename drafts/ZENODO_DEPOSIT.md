# Zenodo deposit — prep + click steps (DO NOT auto-run; for Scott)

Launch rule: no agent deposits anything. This is the checklist for Scott to get
a citable **DOI** for hwattest + the hwattest-eval dataset. Two common routes;
pick one.

## Before depositing (do these first)
1. Decide author ORCID(s); put them in `CITATION.cff` and
   `drafts/zenodo_dataset_paper.md`.
2. Confirm the dataset is clean (identifier gate must pass):
   ```bash
   .venv-dev/bin/python eval/verify_no_identifiers.py 'eval/data/local/*.jsonl'
   # must print "CLEAN: 41 record(s) ... no machine identifiers found."
   ```
3. Confirm results are current:
   ```bash
   .venv-dev/bin/python eval/evaluate.py eval/data/local/*.jsonl --out eval/results/local_metrics.json
   .venv-dev/bin/python eval/replay.py --trials 10 --out eval/results/replay.json
   git status --porcelain   # expect no diff if results already committed
   ```
4. Make sure the GitHub repo is public (see QUEUE.jsonl: `hwattest-create-repo`,
   `hwattest-push`). Zenodo's GitHub integration needs a public repo + a release.

## Route A — Zenodo ↔ GitHub (recommended; DOI tracks releases)
Pure UI/manual, no secrets in this repo:
1. Log in to https://zenodo.org with the Elyan Labs / Scott account.
2. Account → **GitHub** → flip the toggle **ON** for `Scottcjn/hwattest`.
   (Zenodo only sees repos you own/admin and that are public.)
3. On GitHub, draft a release and tag it:
   ```bash
   # run by Scott, after the repo is pushed public (queued, not run here)
   gh release create v0.1.0 -R Scottcjn/hwattest \
     --title "hwattest v0.1.0" \
     --notes-file drafts/release_notes_v0.1.0.md   # write this from README intro + eval
   ```
4. Zenodo auto-creates a deposit from the release. Open it, then **Edit** the
   metadata to match `CITATION.cff`: Title, Authors+ORCID, Description (use the
   paper abstract), License = **Apache-2.0**, Keywords, Upload type =
   *Software*. Add a **related identifier**: the dataset record (Route B) as
   "is supplemented by," if you also deposit the dataset separately.
5. **Publish** → Zenodo mints a version DOI + a concept DOI. Put the concept DOI
   back into `CITATION.cff` (`doi:` field) and the README badge, then commit.

## Route B — dataset as its own record (for the data-paper DOI)
Deposit `eval/data/` + `eval/DATASHEET.md` as a standalone dataset record so it
has its own DOI to cite in the paper:
1. Zenodo → **New upload**.
2. Build the upload bundle locally (do not include venvs or caches):
   ```bash
   mkdir -p dist && tar --exclude='.venv*' --exclude='__pycache__' \
     -czf dist/hwattest-eval-1.0.tar.gz \
     eval/data eval/DATASHEET.md eval/collect.py eval/evaluate.py \
     eval/replay.py eval/verify_no_identifiers.py eval/run_local.sh \
     eval/vm/run_guest.sh eval/FLEET_PLAN.md eval/README.md \
     eval/results CITATION.cff LICENSE NOTICE
   ```
3. Upload that tarball. Upload type = **Dataset**. License = Apache-2.0. Title
   = "hwattest-eval/1 ...". Description = datasheet summary. Add related
   identifier → the software record (Route A) as "is supplement to", and the
   GitHub URL.
4. **Publish** → dataset DOI. Add it to `CITATION.cff` `references:` and to the
   paper's Data-availability section.

## After
- Add the DOI badge to README; commit (`git` only — still no auto-publish).
- The paper (`drafts/zenodo_dataset_paper.md`) can then cite both DOIs.

## Reminders
- No raw identifiers ship in the bundle — the gate in step 2 is the guarantee;
  re-run it against the exact files you tar.
- Keep LICENSE + NOTICE in every bundle (lab rule).
- Apache-2.0 everywhere; no token/RTC text anywhere in the metadata or paper.
