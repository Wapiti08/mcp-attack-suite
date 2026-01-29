## Attack Method
### Poison Attack




### Puppet Attack
当用户同时安装了多个 MCP Server 时，攻击者通过一个恶意 MCP Server 的工具描述（tool description），在 LLM 的规划阶段“劫持”或“附加”到另一个被信任的 MCP Server 工具调用上，使得用户以为自己只调用了可信工具，实际上却触发了隐藏的恶意行为 。


### Malicious External Resource
MCP Server 本身的工具代码与工具描述是良性的，但其在执行过程中访问的第三方外部资源（网站 / API / 文档等）被攻击者植入了恶意指令，从而在运行时诱导 LLM 执行非预期或恶意行为。

多模态入口属于这类攻击？？？

## 多模态靶场设计
正常的的MCP
注入了恶意的文件

### email靶场设计


