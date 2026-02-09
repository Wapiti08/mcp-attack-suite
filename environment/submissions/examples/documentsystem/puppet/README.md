# Puppet attack (documentsystem)

Puppet 定义：用户同时安装多个 MCP Server 时，攻击者通过**恶意 MCP Server 的 tool description**在规划阶段劫持/附加到可信工具调用上。

Run:

`python -m environment.arena.runner run --challenge documentsystem --attack puppet --submission environment/submissions/examples/documentsystem/puppet/puppet_doc_provider.py`

