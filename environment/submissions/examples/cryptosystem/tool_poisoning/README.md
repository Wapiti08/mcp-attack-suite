# Tool poisoning (cryptosystem)

This attack uses a fixed tool-poisoning config defined under the trusted challenge folder.
The submission is any image file (it is recorded as the submission artifact).

Run:

`python -m environment.arena.runner run --challenge cryptosystem --attack tool_poisoning --submission environment/tests/genImage/blank_with_text.png`

