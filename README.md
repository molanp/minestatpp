# minestatpp
MineStat的异步版，实现IPv6与多解析查询

## 安装
为了使用方便，此修改版本并不考虑发布到PyPI，因此直接下载脚本即可。

## 最小实例
```python
from minestatpp import Checker
import asyncio


async def main():
    ms = Checker("tzdtwsj.top")
    print(await ms.check())

asyncio.run(main())

# 输出
# [<minestatpp.MineStat object at 0x00000175FC3D62D0>, <minestatpp.MineStat object at 0x00000175FF92F5D0>]
```
**不需要使用`online`参数判断服务器是否在线**，因为如果服务器不可用，将会返回一个空列表，这时可以使用`if`判断服务器是否可用
```python
from minestatpp import Checker
import asyncio


async def main():
    ms = Checker("offline.server.address")
    result = await ms.check()
    if result:
        print(result)
    else:
        print("服务器不在线")

asyncio.run(main())
```

## 完整实例
```python
from minestatpp import Checker
import asyncio


async def main():
    ms = Checker("tzdtwsj.top")
    result = await ms.check()
    for ms in result:
        print("######################################################################")
        print(
            f"Server is online running version {ms.version} with {ms.current_players} out of {ms.max_players} players."
        )
        if ms.gamemode:
            print(f"Game mode: {ms.gamemode}")
        print(f"Message of the day: {ms.motd}")
        print(f"Message of the day without formatting: {ms.stripped_motd}")
        print(f"Latency: {ms.latency}ms")
        print(f"Connected using protocol: {ms.slp_protocol}")

asyncio.run(main())
```
将会输出以下内容
```plaintext
######################################################################
Server is online running version Paper 1.21.4 with 0 out of 20 players.
Message of the day: {"text": "", "extra": [{"text": "tzdt", "color": "yellow"}, {"text": "\u7684", "color": "dark_red"}, {"text": "\u6d4b\u8bd5\u670d\u52a1\u5668", "color": "dark_green"}]}
Message of the day without formatting: tzdt的测试服务器
Latency: 40ms
Connected using protocol: JSON
######################################################################
Server is online running version 1.21.51 Bedrock level (MCPE) with 0 out of 10 players.
Game mode: Survival
Message of the day: 非常好服务器
Message of the day without formatting: 非常好服务器
Latency: 0ms
Connected using protocol: BEDROCK_RAKNET
```

## 参数说明
返回列表中的每一项都是一个在线的MineStat对象，对象中包含属性与MineStat相同

参阅[MineStat](https://github.com/FragLand/minestat/blob/master/Python/README.md)


## 感谢

[MineStat](https://github.com/FragLand/minestat/)

