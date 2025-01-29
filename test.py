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
