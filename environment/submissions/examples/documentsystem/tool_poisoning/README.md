# Tool poisoning (documentsystem)

This attack uses a fixed tool-poisoning config under:

`environment/arena/challenges/documentsystem/attacks/tool_poisoning.json`

The submission is the **injection string** that overrides `tool_poisoning.injection`.

Run:

`python -m environment.arena.runner run --challenge documentsystem --attack tool_poisoning --submission "恶意指令内容"`

