import asyncio
import base64
import json
import os
import ssl
import struct
import time
from typing import Any, Dict, List, Optional, Tuple


def encode_variable_length(length: int) -> bytes:
    """Encodes an integer into the MQTT variable byte length format.

    Args:
        length: The length value to encode.

    Returns:
        The encoded bytes representing the length field.
    """
    output = bytearray()
    while True:
        encoded_byte = length % 128
        length //= 128
        if length > 0:
            encoded_byte |= 0x80
        output.append(encoded_byte)
        if length == 0:
            break
    return bytes(output)


def build_connect_packet(
    client_id: str, username: Optional[str] = None, password: Optional[str] = None
) -> bytes:
    """Constructs a raw MQTT v3.1.1 CONNECT control packet.

    Args:
        client_id: A unique identifier for the connecting client session.
        username: An optional username string for access authentication.
        password: An optional password string or byte sequence.

    Returns:
        The complete byte sequence representing the CONNECT packet.
    """
    variable_header = b"\x00\x04MQTT" + struct.pack("B", 4)
    flags = 0x02

    if password is not None:
        flags |= 0x40
    if username is not None:
        flags |= 0x80

    variable_header += struct.pack("B", flags) + struct.pack(">H", 60)
    payload = struct.pack(">H", len(client_id)) + client_id.encode()

    if username is not None:
        payload += struct.pack(">H", len(username)) + username.encode()
    if password is not None:
        encoded_pwd = password.encode() if isinstance(password, str) else password
        payload += struct.pack(">H", len(encoded_pwd)) + encoded_pwd

    packet_body = variable_header + payload
    return bytes([0x10]) + encode_variable_length(len(packet_body)) + packet_body


def build_subscribe_packet(packet_id: int, topic: str, qos: int = 0) -> bytes:
    """Constructs a raw MQTT SUBSCRIBE control packet for a specific topic filter.

    Args:
        packet_id: The unique packet identifier tracking the request loop.
        topic: The target topic namespace path or wildcard filter.
        qos: The desired Quality of Service level (0, 1, or 2).

    Returns:
        The complete byte sequence representing the SUBSCRIBE packet.
    """
    topic_bytes = topic.encode()
    payload = (
        struct.pack(">H", packet_id)
        + struct.pack(">H", len(topic_bytes))
        + topic_bytes
        + struct.pack("B", qos)
    )
    return bytes([0x82]) + encode_variable_length(len(payload)) + payload


def xor_mask_data(data: bytes, mask: bytes) -> bytes:
    """Applies a 4-byte WebSocket masking key to a raw data payload via XOR operation.

    Args:
        data: The input byte array payload to mask.
        mask: The 4-byte cryptographic masking key sequence.

    Returns:
        The XOR-transformed byte array.
    """
    return bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))


def format_websocket_frame(data: bytes, opcode: int = 0x02) -> bytes:
    """Wraps an internal payload into a valid client-side masked WebSocket frame structure.

    Args:
        data: The internal payload bytes (e.g., an MQTT control packet).
        opcode: The WebSocket frame type code (0x02 denotes a binary payload).

    Returns:
        The complete masked WebSocket frame byte sequence.
    """
    masking_key = os.urandom(4)
    header = bytearray([0x80 | opcode])
    data_length = len(data)

    if data_length < 126:
        header.append(0x80 | data_length)
    elif data_length < 65536:
        header.append(0x80 | 126)
        header.extend(struct.pack(">H", data_length))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack(">Q", data_length))

    header.extend(masking_key)
    return bytes(header) + xor_mask_data(data, masking_key)


async def read_websocket_frame(reader: asyncio.StreamReader) -> Tuple[int, bytes]:
    """Reads and parses an incoming WebSocket frame from the active stream connection.

    Args:
        reader: The asyncio stream reader connected to the target socket.

    Returns:
        A tuple containing the integer frame opcode and the unmasked byte payload.
    """
    first_byte = await reader.readexactly(1)
    opcode = first_byte[0] & 0x0F

    second_byte = await reader.readexactly(1)
    is_masked = bool(second_byte[0] & 0x80)
    payload_length = second_byte[0] & 0x7F

    if payload_length == 126:
        payload_length = struct.unpack(">H", await reader.readexactly(2))[0]
    elif payload_length == 127:
        payload_length = struct.unpack(">Q", await reader.readexactly(8))[0]

    if is_masked:
        masking_key = await reader.readexactly(4)
        raw_payload = await reader.readexactly(payload_length)
        payload_data = xor_mask_data(raw_payload, masking_key)
    else:
        payload_data = await reader.readexactly(payload_length)

    return opcode, payload_data


def parse_publish_payload(raw_data: bytes) -> Dict[str, str]:
    """Extracts the topic and text string contents out of an incoming MQTT PUBLISH packet.

    Args:
        raw_data: The raw packet bytes beginning at the variable length header.

    Returns:
        A dictionary containing the resolved topic name and decoded message text.
    """
    topic_length = struct.unpack(">H", raw_data[0:2])[0]
    topic_name = raw_data[2 : 2 + topic_length].decode("utf-8", errors="replace")
    message_body = raw_data[2 + topic_length :].decode("utf-8", errors="replace")
    return {"topic": topic_name, "message": message_body}


async def execute_mqtt_audit(host: str, port: int, path: str, target_topics: List[str]) -> None:
    """Runs an unauthenticated MQTT audit over WebSockets against an architectural endpoint.

    Args:
        host: The destination target domain name or network IP.
        port: The destination port interface number.
        path: The targeted WebSocket endpoint URI path.
        target_topics: A list of namespace wildcard paths to test subscription rights.
    """
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    print(f"[*] Initiating transport link to wss://{host}:{port}{path}...")
    reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)

    # Handshake generation following WebSocket RFC specifications
    handshake_nonce = base64.b64encode(os.urandom(16)).decode()
    http_upgrade_request = (
        f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {handshake_nonce}\r\nSec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Protocol: mqtt\r\n\r\n"
    )
    writer.write(http_upgrade_request.encode())
    await writer.drain()

    handshake_buffer = b""
    while b"\r\n\r\n" not in handshake_buffer:
        handshake_buffer += await asyncio.wait_for(reader.read(4096), timeout=10)
    print(f"[+] WebSocket Upgrade Status: {handshake_buffer.split(b'\r\n')[0].decode()}")

    # Step 1: Check for Anonymous Authentication Acceptance
    client_session_id = f"audit-{os.urandom(4).hex()}"
    connect_packet = build_connect_packet(client_session_id)
    writer.write(format_websocket_frame(connect_packet))
    await writer.drain()

    _, incoming_frame = await asyncio.wait_for(read_websocket_frame(reader), timeout=10)
    return_code = incoming_frame[3] if len(incoming_frame) >= 4 else -1
    print(f"[+] Broker Response - CONNACK code={return_code}")

    if return_code != 0:
        print("[-] Access Blocked: Authentication required by endpoint.")
        writer.close()
        return

    print("[+] Status Check: Anonymous access allowed (CWE-306 verified).")

    # Step 2: Validate global or namespace authorization controls
    for index, topic in enumerate(target_topics):
        subscribe_packet = build_subscribe_packet(index + 1, topic)
        writer.write(format_websocket_frame(subscribe_packet))
        await writer.drain()
        try:
            _, suback_frame = await asyncio.wait_for(read_websocket_frame(reader), timeout=5)
            is_allowed = suback_frame[4] != 128 if len(suback_frame) >= 5 else False
            print(f"    - Topic Filter '{topic}': {'Subscribed' if is_allowed else 'Rejected'}")
        except asyncio.TimeoutError:
            print(f"    - Topic Filter '{topic}': Timeout (No response)")

    # Step 3: Monitor incoming data stream for lack of structural restriction
    print("[*] Monitoring inbound message queues (30-second window)...")
    start_time = time.time()
    message_count = 0

    while time.time() - start_time < 30 and message_count < 20:
        try:
            _, frame_data = await asyncio.wait_for(read_websocket_frame(reader), timeout=5)
            # Identify if the message frame is an MQTT PUBLISH packet (0x30 control type)
            if (frame_data[0] & 0xF0) == 0x30:
                parsed_packet = parse_publish_payload(frame_data[2:])
                message_count += 1
                print(f"  [{message_count}] Discovered Event on Topic: {parsed_packet['topic']}")
                if parsed_packet["message"]:
                    print(f"      Payload Excerpts: {parsed_packet['message'][:150]}")
        except asyncio.TimeoutError:
            continue
        except Exception as error:
            print(f"[-] Pipeline interruption during capture: {error}")
            break

    print(f"\n[RESULT] Verification complete. Captured {message_count} stream items.")
    writer.close()


if __name__ == "__main__":
    # Parametrized configuration variables for generic local or deployment audits
    TARGET_HOST = os.getenv("TARGET_MQTT_HOST", "broker.example.com")
    TARGET_PORT = int(os.getenv("TARGET_MQTT_PORT", "1883"))
    TARGET_PATH = os.getenv("TARGET_MQTT_PATH", "/mqtt")
    
    # Generic operational topic patterns for infrastructure testing
    AUDIT_TOPICS = ["devices/#", "users/#", "telemetry/#"]

    try:
        asyncio.run(execute_mqtt_audit(TARGET_HOST, TARGET_PORT, TARGET_PATH, AUDIT_TOPICS))
    except KeyboardInterrupt:
        print("\n[-] Operational scan terminated by user command.")