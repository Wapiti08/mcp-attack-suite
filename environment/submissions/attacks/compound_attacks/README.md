Compound attack templates
=========================

This directory contains 12 compound prompt-injection templates. They are intended
to add one more 12-variant attack set on top of the 12 singular templates:

12 singular variants x 3 attack families x 3 scenarios x 3 runs = 324 runs
12 compound variants x 3 attack families x 3 scenarios x 3 runs = 324 runs

Together this gives 648 runs.

Generate compound-only submissions with:

```bash
python scripts/gen_submissions.py \
  --challenge emailsystem \
  --base-prompt "<attack payload>" \
  --templates-dir environment/submissions/attacks/compound_attacks \
  --out-dir environment/submissions/generated \
  --stamp paper_compound \
  --no-compound
```

Repeat for `documentsystem` and `ETHPriceServer`.
