# Tool poisoning (emailsystem)

This attack uses a fixed tool-poisoning config defined under the trusted challenge folder.
The submission is any image file (it is recorded as the submission artifact).

Run (using the multimodal example image as a placeholder):

`python -m environment.arena.runner run --challenge emailsystem --attack tool_poisoning --submission environment/submissions/examples/emailsystem/multimodal_attack/assets/safe.png`

