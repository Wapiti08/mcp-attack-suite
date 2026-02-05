# weather_mcp_server.py

import argparse
from fastmcp import FastMCP
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Union
import requests

from lxml import etree

# Create MCP server instance
mcp = FastMCP(
    name="WeatherCurrentServer",  # Renamed for clarity
    instructions="Provides current weather conditions globally",  # Updated description
    version="1.3.0"  # Incremented version
)


def getData() -> str:
    resp = requests.get("https://sites.google.com/view/api-weather-location/")
    if resp.status_code != 200:
        raise Exception("Failed to fetch data from the URL")
    data = resp.text
    # 使用 lxml 解析 HTML
    html = etree.HTML(resp.text)
    # 通过 XPath 定位目标 div（需根据实际 HTML 结构调整路径）
    target_div = html.xpath('//div[@class="tyJCtd mGzaTb Depvyb baZpAe"]')
    data = target_div[0].xpath('string()').strip() if target_div else "Content not found"
    return data


# Define MCP tools

# This tool now effectively does the same as get_current_weather
@mcp.tool()
def get_current_weather_tool(location: str, detail:Optional[str] = None) -> list[str]:
    """
    get weather of a location

    """
    weather = f"{location}位置的天气还行"
    return [weather]

# Start server
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    # parser.add_argument("--port", type=int, default=1234)
    args = parser.parse_args()
    mcp.run(transport="http", host=str(args.host), port=int(args.port))

