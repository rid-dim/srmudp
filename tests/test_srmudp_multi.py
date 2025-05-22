import pytest
import time
import threading
from typing import Dict, List, Optional, Tuple, Any
from srmudp import SecureReliableSocket  # Assuming the refactored class exists

# Define a type alias for the received message structure
class ReceivedMessage:
    peer: str
    content: bytes
    timestamp: float

    def __init__(self, peer: str, content: bytes, timestamp: float):
        self.peer = peer
        self.content = content
        self.timestamp = timestamp

# Fixture to create and cleanup sockets
@pytest.fixture
def sockets():
    """Creates four SecureReliableSocket instances for testing."""
    sock_a = SecureReliableSocket(port=7777)
    sock_b = SecureReliableSocket(port=7778)
    sock_c = SecureReliableSocket(port=7779)
    sock_d = SecureReliableSocket(port=7780, peers={"A": "127.0.0.1:7777", "B": "127.0.0.1:7778", "C": "127.0.0.1:7779"})
    
    sockets_dict = {"A": sock_a, "B": sock_b, "C": sock_c, "D": sock_d}
    
    yield sockets_dict
    
    # Cleanup: close all sockets
    for sock in sockets_dict.values():
        try:
            sock.close()
        except Exception as e:
            print(f"Error closing socket: {e}") # Use print for fixture cleanup output
    # Allow some time for sockets to close properly
    time.sleep(0.5)

# Helper function to establish connections between all peers in the tests
def establish_all_connections(sockets: Dict[str, SecureReliableSocket]):
    sock_a = sockets["A"]
    sock_b = sockets["B"]
    sock_c = sockets["C"]
    sock_d = sockets["D"] # D already knows A, B, C from its init

    # A needs to know B, C, D
    sock_a.add_peers({"B": "127.0.0.1:7778", "C": "127.0.0.1:7779", "D": "127.0.0.1:7780"})
    # B needs to know A, C, D
    sock_b.add_peers({"A": "127.0.0.1:7777", "C": "127.0.0.1:7779", "D": "127.0.0.1:7780"})
    # C needs to know A, B, D
    sock_c.add_peers({"A": "127.0.0.1:7777", "B": "127.0.0.1:7778"})
    sock_c.add_peers({"D": "127.0.0.1:7780"})
    # D needs to know A, B, C (already done via constructor in this setup)

    # Allow time for connections to establish
    # Increased time slightly for more peers
    time.sleep(7)

@pytest.mark.timeout(40) # Increased timeout slightly
def test_initialization_and_connection(sockets: Dict[str, SecureReliableSocket]):
    """Tests basic initialization and peer connection via constructor and add_peers."""
    # Use the helper to establish connections
    establish_all_connections(sockets)

    sock_a = sockets["A"]
    sock_b = sockets["B"]
    sock_c = sockets["C"]
    sock_d = sockets["D"]

    # Verify connections (assuming connections_status provides useful info)
    status_a = sock_a.connections_status
    status_b = sock_b.connections_status
    status_c = sock_c.connections_status
    status_d = sock_d.connections_status

    assert "B" in status_a and status_a["B"]["established"]
    assert "C" in status_a and status_a["C"]["established"]
    assert "D" in status_a and status_a["D"]["established"]

    assert "A" in status_b and status_b["A"]["established"]
    assert "C" in status_b and status_b["C"]["established"]
    assert "D" in status_b and status_b["D"]["established"]

    assert "A" in status_c and status_c["A"]["established"]
    assert "B" in status_c and status_c["B"]["established"]
    assert "D" in status_c and status_c["D"]["established"]

    assert "A" in status_d and status_d["A"]["established"]
    assert "B" in status_d and status_d["B"]["established"]
    assert "C" in status_d and status_d["C"]["established"]

@pytest.mark.timeout(40)
def test_send_to_all(sockets: Dict[str, SecureReliableSocket]):
    """Tests sending a message to all connected peers (B, C, D)."""
    # Establish connections using the helper
    establish_all_connections(sockets)

    sock_a = sockets["A"]
    sock_b = sockets["B"]
    sock_c = sockets["C"]
    sock_d = sockets["D"]

    message_content = b"message to all peers"
    sock_a.send(message_content) # Send to all implicitly

    # Check reception on B, C, and D
    received_b = sock_b.receive(timeout=2.0)
    received_c = sock_c.receive(timeout=2.0)
    received_d = sock_d.receive(timeout=2.0)

    assert received_b is not None
    assert received_b.peer == "A"
    assert received_b.content == message_content
    assert isinstance(received_b.timestamp, float)

    assert received_c is not None
    assert received_c.peer == "A"
    assert received_c.content == message_content
    assert isinstance(received_c.timestamp, float)

    assert received_d is not None
    assert received_d.peer == "A"
    assert received_d.content == message_content
    assert isinstance(received_d.timestamp, float)

    # Check that A doesn't receive its own message
    received_a = sock_a.receive(timeout=0.5)
    assert received_a is None

@pytest.mark.timeout(40)
def test_send_to_subset(sockets: Dict[str, SecureReliableSocket]):
    """Tests sending a message to a specific subset of peers (B, C), excluding D."""
    # Establish connections using the helper
    establish_all_connections(sockets)

    sock_a = sockets["A"]
    sock_b = sockets["B"]
    sock_c = sockets["C"]
    sock_d = sockets["D"]

    message_content = b"targeted message to B and C"
    sock_a.send(message_content, recipient=["B", "C"])

    # Check reception on B and C
    received_b = sock_b.receive(timeout=2.0)
    received_c = sock_c.receive(timeout=2.0)

    assert received_b is not None
    assert received_b.peer == "A"
    assert received_b.content == message_content

    assert received_c is not None
    assert received_c.peer == "A"
    assert received_c.content == message_content

    # Check that D did *not* receive the message
    received_d = sock_d.receive(timeout=1.0)
    assert received_d is None, "Peer D should not have received the message sent to subset [B, C]"

    # Check that A doesn't receive its own message
    received_a = sock_a.receive(timeout=0.5)
    assert received_a is None

@pytest.mark.timeout(40)
def test_send_to_single_recipient(sockets: Dict[str, SecureReliableSocket]):
    """Tests sending a message to a single specific peer (B), excluding C and D."""
    # Establish connections using the helper
    establish_all_connections(sockets)

    sock_a = sockets["A"]
    sock_b = sockets["B"]
    sock_c = sockets["C"]
    sock_d = sockets["D"]

    message_content = b"private message to B"
    sock_a.send(message_content, recipient=["B"])

    # Check reception on B
    received_b = sock_b.receive(timeout=2.0)
    assert received_b is not None
    assert received_b.peer == "A"
    assert received_b.content == message_content

    # Check that C did *not* receive the message
    received_c = sock_c.receive(timeout=1.0)
    assert received_c is None, "Peer C should not have received the message sent only to B"

    # Check that D did *not* receive the message
    received_d = sock_d.receive(timeout=1.0)
    assert received_d is None, "Peer D should not have received the message sent only to B"

    # Check that A doesn't receive its own message
    received_a = sock_a.receive(timeout=0.5)
    assert received_a is None

@pytest.mark.timeout(45) # Increased timeout for removal test
def test_remove_peer(sockets: Dict[str, SecureReliableSocket]):
    """Tests dynamically removing a peer and checks others remain connected."""
    # Establish connections using the helper
    establish_all_connections(sockets)

    sock_a = sockets["A"]
    sock_b = sockets["B"]
    sock_c = sockets["C"]
    sock_d = sockets["D"]

    # Verify initial state (A<->B)
    assert "B" in sock_a.connections_status and sock_a.connections_status["B"]["established"]
    assert "A" in sock_b.connections_status and sock_b.connections_status["A"]["established"]
    # Verify initial state (A<->D)
    assert "D" in sock_a.connections_status and sock_a.connections_status["D"]["established"]
    assert "A" in sock_d.connections_status and sock_d.connections_status["A"]["established"]

    # A removes B
    sock_a.remove_peers(["B"])
    # B should also remove A or detect the closure
    sock_b.remove_peers(["A"]) # Explicitly remove on both sides for clarity

    time.sleep(5) # Allow time for removal propagation/cleanup

    # Verify B is removed from A's status
    status_a = sock_a.connections_status
    assert "B" not in status_a or not status_a["B"]["established"] # Check if key removed or status changed

    # Verify A is removed from B's status
    status_b = sock_b.connections_status
    assert "A" not in status_b or not status_b["A"]["established"]

    # Verify A and C can still communicate
    message_to_c = b"message to C after B removed"
    sock_a.send(message_to_c, recipient=["C"])
    received_c = sock_c.receive(timeout=2.0)
    assert received_c is not None
    assert received_c.peer == "A"
    assert received_c.content == message_to_c

    # Verify A and D can still communicate
    message_to_d = b"message to D after B removed"
    sock_a.send(message_to_d, recipient=["D"])
    received_d_after_b_removed = sock_d.receive(timeout=2.0)
    assert received_d_after_b_removed is not None
    assert received_d_after_b_removed.peer == "A"
    assert received_d_after_b_removed.content == message_to_d

    # Verify B cannot receive from A anymore
    message_to_b_after_remove = b"should not arrive"
    # Use try-except in case send raises an error for unknown peer
    try:
        sock_a.send(message_to_b_after_remove, recipient=["B"]) # Attempt to send
    except KeyError: # Or specific exception defined by the implementation
        pass # Expected if peer is fully removed internally before send checks
    received_b_after = sock_b.receive(timeout=1.0)
    assert received_b_after is None

@pytest.mark.timeout(30)
def test_message_hook(sockets: Dict[str, SecureReliableSocket]):
    """Tests the hook mechanism for incoming messages (replaces old broadcast fn)."""
    # This test only uses A and B, no change needed for sock_d unless hook behavior changes
    sock_a = sockets["A"]
    sock_b = sockets["B"]

    received_messages_b: List[ReceivedMessage] = []
    hook_called_event = threading.Event()

    def message_hook_b(message: ReceivedMessage):
        """Callback function to be registered as a hook."""
        nonlocal received_messages_b
        print(f"Hook called on B: Peer={message.peer}, Content={message.content}") # Debug print
        received_messages_b.append(message)
        hook_called_event.set() # Signal that the hook was called

    # Register the hook on sock_b
    sock_b.register_message_hook(message_hook_b)

    # Establish connection (Only A and B needed for this specific test)
    sock_a.add_peers({"B": "127.0.0.1:7778"})
    sock_b.add_peers({"A": "127.0.0.1:7777"})
    # No need to connect C or D for this test case
    time.sleep(5) # Allow connection time

    # Send a message from A to B
    message_content = b"message for hook"
    sock_a.send(message_content, recipient=["B"])

    # Wait for the hook to be called (with a timeout)
    hook_was_called = hook_called_event.wait(timeout=5.0)
    assert hook_was_called, "Message hook was not called within timeout"

    # Verify the message was received via the hook
    assert len(received_messages_b) == 1
    received_message = received_messages_b[0]
    assert received_message.peer == "A"
    assert received_message.content == message_content
    assert isinstance(received_message.timestamp, float)

    # Verify that receive() does not get the message if hook is used
    message_via_receive = sock_b.receive(timeout=0.5)
    assert message_via_receive is None, "Message should have been consumed by the hook, not receive()"

# Note: The exact structure of `connections_status` and the precise behavior
# of `receive()` when a hook is registered might differ in the final implementation.
# These tests assume the behavior described in the markdown concept.
# Timings (sleep durations) might need adjustment based on the actual implementation's speed.
# Error handling for connection failures is not explicitly tested here but is crucial.
# Type hints assume `receive` returns an object with `peer`, `content`, `timestamp` attributes.
# MyPy annotations added assuming `srmudp.SecureReliableSocket` provides these methods and types. 