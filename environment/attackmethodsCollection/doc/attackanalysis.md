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

这里有些问题。就是,

首先,

我需要一个目的 + 基本的攻击方式？？？

比如说 现在就看这个邮件系统

邮件系统的四种攻击方式：



更简单一点？天气

- tool poisoning
- puppet attack
- cross-model



我现在的server是固定的，需要改的就是 PROMPT

比如现在我们固定email，
1. tool poisoning
2. puppet attack


用户输入的是正常输入？？？那个之后再考虑、
就先比如说 发送之前 总结5封邮件发送给xxx


1. 删除 insecure prompt
2. 

PROMPT那个方面


5 x 4 x 10
先不考虑 10
先考虑 5  x 4


针对不同的靶场 要生成不同的prompt 并且要实现4种类攻击
解题人通过实现下面的攻击，来实现目标
- tool poisoning
- puppet attack