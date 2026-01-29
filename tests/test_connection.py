from openai import OpenAI

base_url = "http://localhost:1234/v1/"
model = "meta-llama-3.1-8b-instruct"

client = OpenAI(
    base_url=base_url,  # 你的本地或代理 URL
    api_key="lm-studio"
)

resp = client.chat.completions.create(
    model=model,
    messages=[
        {"role": "user", "content": "你好，本地服务！"}
    ]
)
print(resp.choices[0].message.content)