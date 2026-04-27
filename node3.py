import server
import asyncio

node = server.DSANNode("C", 9003)
node.known_peers["A"] = ("127.0.0.1", 9001)
node.known_peers["B"] = ("127.0.0.1", 9002)


async def main():
    await asyncio.sleep(1)
    for pid, (host, port) in node.known_peers.items():
        if pid != node.node_id:
            await node.connect_to_peer(host, port)

asyncio.gather(
    node.start(),
    main()
).get_loop().run_forever()