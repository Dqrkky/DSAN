import asyncio, json, time, os

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ================= CRYPTO =================

def hkdf(shared):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"dsan-v1"
    ).derive(shared)

def encrypt(key, obj):
    aes = AESGCM(key)
    nonce = os.urandom(12)
    data = json.dumps(obj).encode()
    return {
        "nonce": nonce.hex(),
        "data": aes.encrypt(nonce, data, None).hex()
    }

def decrypt(key, msg):
    aes = AESGCM(key)
    return json.loads(
        aes.decrypt(bytes.fromhex(msg["nonce"]), bytes.fromhex(msg["data"]), None)
    )

# ================= NODE =================

class DSANNode:
    def __init__(self, node_id :str=None, host :str=None, port :int=None):
        self.node_id = node_id if node_id != None and isinstance(node_id, str) else os.urandom(4).hex()
        self.host = host if host != None and isinstance(host, str) else "localhost"
        self.port = port if port != None and isinstance(port, int) else 9000

        self.sign_priv = ed25519.Ed25519PrivateKey.generate()
        self.sign_pub = self.sign_priv.public_key()

        self.trusted = {}     # node_id -> pubkey
        self.sessions = {}    # node_id -> session_key
        self.known_peers = {} # node_id -> (host, port)

    def pub_bytes(self):
        return self.sign_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    # ================= HANDSHAKE =================

    def create_handshake(self):
        self.ecdh_priv = x25519.X25519PrivateKey.generate()
        self.ecdh_pub = self.ecdh_priv.public_key()

        pub_bytes = self.ecdh_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        timestamp = int(time.time())

        payload = (
            self.node_id.encode() +
            pub_bytes +
            str(timestamp).encode()
        )

        signature = self.sign_priv.sign(payload)

        return {
            "node_id": self.node_id,
            "host": self.host,
            "port": self.port,
            "ecdh": pub_bytes.hex(),
            "sign_pub": self.pub_bytes().hex(),
            "timestamp": timestamp,
            "signature": signature.hex()
        }

    def verify_handshake(self, data :dict=None):

        # Node ID
        node_id :str = data.get("node_id", None)
        if node_id == None or isinstance(node_id, str) == False:
            raise Exception("Invalid handshake: missing node_id")

        # Host
        host :str = data.get("host", None)
        if host == None or isinstance(host, str) == False:
            raise Exception("Invalid handshake: missing host")

        # Port
        port :int = data.get("port", None)
        if port == None or isinstance(port, int) == False:
            raise Exception("Invalid handshake: missing port")

        # ECDH
        ecdh :str = data.get("ecdh", None)
        if ecdh == None or isinstance(ecdh, str) == False:
            raise Exception("Invalid handshake: missing ecdh")

        # Sign Pubkey
        sign_pub :str = data.get("sign_pub", None)
        if sign_pub == None or isinstance(sign_pub, str) == False:
            raise Exception("Invalid handshake: missing sign_pub")

        # Signature
        signature :str = data.get("signature", None)
        if signature == None or isinstance(signature, str) == False:
            raise Exception("Invalid handshake: missing signature")

        # Timestamp
        timestamp :int = data.get("timestamp", None)
        if timestamp == None or isinstance(timestamp, int) == False:
            raise Exception("Invalid handshake: missing timestamp")

        # Replay attack prevention (30s window)
        if abs(time.time() - timestamp) > 30:
            raise Exception("Replay attack")

        # Convert hex to bytes for crypto operations
        ecdh = bytes.fromhex(ecdh)
        sign_pub = bytes.fromhex(sign_pub)
        signature = bytes.fromhex(signature)

        verify_key = ed25519.Ed25519PublicKey.from_public_bytes(sign_pub)

        payload = (
            node_id.encode() +
            host.encode() +
            str(port).encode() +
            ecdh +
            str(timestamp).encode()
        )

        verify_key.verify(signature, payload)

        # Trust / pinning
        if node_id in self.trusted:
            if self.trusted[node_id] != sign_pub:
                raise Exception("MITM detected")
        else:
            print(f"[{self.node_id}] Trusting new peer {node_id}")
            self.trusted[node_id] = sign_pub

        return node_id, host, port, ecdh

    def derive_session(self, peer_ecdh):
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_ecdh)
        shared = self.ecdh_priv.exchange(peer_pub)
        return hkdf(shared)

    # ================= DISCOVERY =================

    async def send_peer_list(self, writer, key):
        msg = {
            "type": "peers",
            "peers": self.known_peers
        }
        enc = encrypt(key, msg)
        writer.write((json.dumps(enc) + "\n").encode())
        await writer.drain()

    async def handle_peer_list(self, data):
        new_peers = data.get("peers", {})
        if new_peers == None or isinstance(new_peers, dict) == False:
            raise Exception("Invalid peer list")

        for pid, (host, port) in new_peers.items():
            if pid == self.node_id:
                continue

            if pid not in self.known_peers:
                print(f"[{self.node_id}] Discovered {pid} at {host}:{port}")
                self.known_peers[pid] = (host, port)

                # Auto-connect
                asyncio.create_task(self.connect_to_peer(host, port))

    # ================= NETWORK =================

    async def handle_peer(self, reader, writer):
        try:
            data = await reader.readline()
            peer_hello = json.loads(data)

            peer_id, host, port, peer_ecdh = self.verify_handshake(peer_hello)

            self.known_peers[peer_id] = (host, port)

            # Send handshake
            my_hello = self.create_handshake()
            writer.write((json.dumps(my_hello) + "\n").encode())
            await writer.drain()

            key = self.derive_session(peer_ecdh)
            self.sessions[peer_id] = key

            print(f"[{self.node_id}] Secure with {peer_id}")

            # Send peer list immediately
            await self.send_peer_list(writer, key)

            while True:
                data = await reader.readline()
                if not data:
                    break

                msg = json.loads(data)
                decrypted = decrypt(key, msg)

                if decrypted.get("type") == "peers":
                    await self.handle_peer_list(decrypted)
                else:
                    print(f"[{self.node_id}] From {peer_id}:", decrypted)

        except Exception as e:
            print(f"[{self.node_id}] ERROR:", e)

        writer.close()

    async def connect_to_peer(self, host: str, port: int):
        try:
            reader, writer = await asyncio.open_connection(host, port)

            hello = self.create_handshake()
            writer.write((json.dumps(hello) + "\n").encode())
            await writer.drain()

            data = await reader.readline()
            peer_hello = json.loads(data)

            peer_id, host, port, peer_ecdh = self.verify_handshake(peer_hello)

            self.known_peers[peer_id] = (host, port)

            key = self.derive_session(peer_ecdh)
            self.sessions[peer_id] = key

            print(f"[{self.node_id}] Connected to {peer_id}")

            # Send peer list
            await self.send_peer_list(writer, key)

            # Send hello message
            data = {
                "type": "hello_ack",
                "event": "connected",
                "node_id": self.node_id,
                "src": {
                    "host": self.host,
                    "port": self.port
                },
                "dest": {
                    "host": host,
                    "port": port
                },
            }
            msg = encrypt(key, data)
            writer.write((json.dumps(msg) + "\n").encode())
            await writer.drain()
            return {
                "status": "ok",
                "peer_id": peer_id,
                **data
            }

        except Exception as e:
            print(f"[{self.node_id}] Connect failed:", e)

    async def start(self):
        server = await asyncio.start_server(
            self.handle_peer, self.host, self.port
        )

        print(f"[{self.node_id}] Listening on {self.port}")

        async with server:
            await server.serve_forever()