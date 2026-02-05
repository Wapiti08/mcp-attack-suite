# Tool poisoning (emailsystem)

This attack uses a fixed tool-poisoning config defined under the trusted challenge folder.
The submission is the **injection string** that will override `tool_poisoning.injection` in:

`environment/arena/challenges/emailsystem/attacks/tool_poisoning.json`

Run:

`python -m environment.arena.runner run --challenge emailsystem --attack tool_poisoning --submission "恶意指令内容"`
