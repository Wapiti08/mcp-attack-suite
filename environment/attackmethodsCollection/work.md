## 工作记录
### 11.9
- 先跑一下 Securing AI Agents with Information-Flow Control https://arxiv.org/abs/2505.23643
- 思考如何从tools agent迁移到MCP上来
- 实现本地小模型调用utils
- Pydantic models (BaseModel subclasses)是什么？（参考https://github.com/modelcontextprotocol/python-sdk
- 先实现简单的版本 然后一步步查找怎么从SDK --> 添加控制？？？？


### 11.10
#### 理解论文中的建模
- 论文对于tools调用进行了建模 
- 而我们的建模对象 --> MCP 是否可以看成更高层次的 tools call 
- 在实现的过程中，我们要如何对MCP进行建模？？？

#### 理解论文中的建模

```text
Msg ::= 
    | User str
    | Tool str
    | ToolCall 𝓕 str*
    | Assistant str
```

任务：

重新阅读 
Joe-E: A Security-Oriented Subset of Java
看看能不能把这个思想用过来


### 11.11
- 先不安排

### 11.13

### 11.20
1. 首先读论文 《Beyond the Protocol: Unveiling Attack Vectors
in the Model Context Protocol (MCP) Ecosystem》，然后看代码


确定攻击类型有哪些？？？
继续跑原来的代码

- Tool Poisoning Attacks
- Puppet Attacks
- Rug Pull Attacks
- Exploitation


- 外部的source如何建模
- 执行的角度 action 如何建模

攻击包含：
- MCP客户端（Cherry Studio、Claude Desktop、Cline、Copilot-MCP、Cursor）
- LLM 提供商（Claude 3.7 Sonnet、GPT-4o、DeepSeek-V3 0324、LLaMA3.1-70B、Gemini 2.5 Pro）
- MCP 服务器（实现攻击向量）

是不是要给它抽象出来？？？
调用这块是黑盒的 所以dual model要做什么改变？？？


也早就说了 是从设计上解决问题
但是非侵入式 能不能做得到呢？？？

AgentDojo benchmark
MCPTox benchmark

形式化定义
安全架构
参考比赛

### 11.23
还要去整合MCP协议？？？
比如，去实现client

https://modelcontextprotocol.io/docs/develop/build-client

在开发这个client的时候，去形式化一下。
```text
Msg ::= 
    | User str
    | Tool str
    | ToolCall 𝓕 str*
    | Assistant str
```

client?
他这篇论文特殊的点在哪？？？

```text
[[M]] : Msg* → ToolCall 𝓕 str* | Assistant str
```
模型 M 是一个根据历史消息决定下一步要说什么或调用什么工具的函数。

来看一下这个MCP

自己编写个client，然后形式化一下？？？？？



### 12.4
Read:
https://embracethered.com/blog/posts/2025/model-context-protocol-security-risks-and-exploits/
https://embracethered.com/blog/posts/2025/windsurf-dangers-lack-of-security-controls-for-mcp-server-tool-invocation/
https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/


### 12.5
- 构建攻击的时候语言得都用中文（why）
- 其实攻击 只和server 有关系

- 细化 control flow


- benchmark(考虑我们怎么用)
- https://github.com/microsoft/presidio


## 12.11

MCP Attack Suite: Simulating Tool Poisoning, Puppet Injection, and Cross-Model Jailbreaks in Secure Execution Pipelines

思考怎么做一个好的？测量？？？
https://blackhat.com/eu-25/briefings/schedule/?track[]=ai-ml--data-science#mcp-unchained-compromising-the-ai-agent-ecosystem-via-its-universal-connector-49228
模拟？
把信息流这一小块 单独拿出来？？？
### 

MCP实现
- Planner
- Loop

planner


MCP 只负责
拿tools
我是不是可以设计不同的

## 下一步
需要：增添一些打标功能？？？
0.0 

https://www.codeintegrity.ai/blog/mcp-tool-calls-security

MCP 系统的污点分析？？？
扫描后，标上 source 和 sink

需要生成调用图。在调用图上做分析
这个调用图张什么样是不是很有说法

tool -> tool

sink: send_email
source: 扫描出来后危险的tools, 或者潜在能被操纵的？？？



