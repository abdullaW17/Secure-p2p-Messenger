"""
File: src/security_utils.py
Purpose: Security utility functions for the I2I P2P application.

This module provides defensive security controls including:
- Input validation for all user-supplied data
- Filename sanitization to prevent path traversal attacks
- Rate limiting using a token bucket algorithm
- Message and file size enforcement
- I2P address format validation
- DoS protection mechanisms

Security Controls:
- All external inputs pass through this module before processing
- Reject malformed data at the earliest point (fail-fast)
- Rate limiting prevents flooding/DoS from a single peer
- Filename sanitization prevents directory traversal (../../../etc/passwd)
"""

import os
import re
import time
import logging
import hashlib
from pathlib import Path
from collections import defaultdict
from typing import Dict, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  Constants / Limits
# ─────────────────────────────────────────────
MAX_MESSAGE_SIZE_BYTES = 4 * 1024          # 4 KB
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024    # 50 MB
MAX_FILENAME_LENGTH = 255
B32_I2P_PATTERN = re.compile(r'^[a-z2-7]{52}\.b32\.i2p$')
HEX_PUBLIC_KEY_PATTERN = re.compile(r'^[0-9a-fA-F]{64}$')

# Rate limiting — token bucket
RATE_LIMIT_CAPACITY = 20       # Maximum tokens per peer
RATE_LIMIT_REFILL_RATE = 5     # Tokens added per second
RATE_LIMIT_COST = 1            # Tokens consumed per message


# ─────────────────────────────────────────────
#  Rate Limiter (Token Bucket)
# ─────────────────────────────────────────────

class RateLimiter:
    """
    Token bucket rate limiter to prevent message flooding from a single peer.

    Purpose: Mitigates DoS attacks where a malicious peer sends messages at very high rates.

    Security:
    - Each peer_id gets its own bucket.
    - Sending a message costs 1 token.
    - Tokens refill at RATE_LIMIT_REFILL_RATE per second, capped at RATE_LIMIT_CAPACITY.
    """

    def __init__(self) -> None:
        # {peer_id: {"tokens": float, "last_refill": float}}
        self._buckets: Dict[str, dict] = defaultdict(
            lambda: {"tokens": float(RATE_LIMIT_CAPACITY), "last_refill": time.monotonic()}
        )

    def is_allowed(self, peer_id: str) -> bool:
        """
        Check whether the given peer is allowed to send another message right now.

        Inputs:
            peer_id: Unique identifier string for the sending peer.
        Output:
            True if the peer is within rate limits, False if rate-limited.
        """
        bucket = self._buckets[peer_id]
        now = time.monotonic()
        elapsed = now - bucket["last_refill"]

        # Refill tokens proportionally to elapsed time
        bucket["tokens"] = min(
            RATE_LIMIT_CAPACITY,
            bucket["tokens"] + elapsed * RATE_LIMIT_REFILL_RATE
        )
        bucket["last_refill"] = now

        if bucket["tokens"] >= RATE_LIMIT_COST:
            bucket["tokens"] -= RATE_LIMIT_COST
            return True

        logger.warning("Rate limit exceeded for peer: %s", _anonymize_id(peer_id))
        return False

    def reset(self, peer_id: str) -> None:
        """
        Reset the rate limit bucket for a peer (e.g., on disconnect).

        Inputs:
            peer_id: Peer identifier to reset.
        """
        if peer_id in self._buckets:
            del self._buckets[peer_id]


# Global rate limiter instance
rate_limiter = RateLimiter()


# ─────────────────────────────────────────────
#  Input Validation
# ─────────────────────────────────────────────

def validate_message(message: str) -> str:
    """
    Validate a user-supplied chat message.

    Security checks:
    - Must be a non-empty string.
    - Must not exceed MAX_MESSAGE_SIZE_BYTES.
    - Strips leading/trailing whitespace.

    Inputs:
        message: Raw message string from the user.
    Output:
        Stripped, validated message string.
    Raises:
        ValueError: If the message is invalid.
    """
    if not isinstance(message, str):
        raise ValueError("Message must be a string.")
    message = message.strip()
    if not message:
        raise ValueError("Message cannot be empty.")
    encoded = message.encode("utf-8")
    if len(encoded) > MAX_MESSAGE_SIZE_BYTES:
        raise ValueError(
            f"Message exceeds maximum size of {MAX_MESSAGE_SIZE_BYTES} bytes."
        )
    return message


def validate_peer_address(address: str) -> str:
    """
    Validate an I2P .b32.i2p peer address format.

    Security checks:
    - Must match the pattern: 52 Base32 characters followed by .b32.i2p
    - Prevents injection of arbitrary hostnames or paths.

    Inputs:
        address: Raw peer address string supplied by the user.
    Output:
        Lowercase stripped address.
    Raises:
        ValueError: If the address format is invalid.
    """
    if not isinstance(address, str):
        raise ValueError("Peer address must be a string.")
    address = address.strip().lower()
    if not B32_I2P_PATTERN.match(address):
        raise ValueError(
            "Invalid peer address format. Expected: <52chars>.b32.i2p"
        )
    return address


def validate_public_key_hex(hex_str: str) -> str:
    """
    Validate a public key supplied as a 64-character hex string.

    Security:
    - Must be exactly 64 hex digits (= 32 bytes, X25519 public key size).
    - Rejects any extra characters.

    Inputs:
        hex_str: User-supplied hex string for the peer's public key.
    Output:
        Lowercase normalized hex string.
    Raises:
        ValueError: If format is invalid.
    """
    if not isinstance(hex_str, str):
        raise ValueError("Public key must be a string.")
    hex_str = hex_str.strip().lower()
    if not HEX_PUBLIC_KEY_PATTERN.match(hex_str):
        raise ValueError("Invalid public key. Must be 64 hex characters.")
    return hex_str


def validate_file_path(file_path: str | Path) -> Path:
    """
    Validate a file path supplied for transmission.

    Security checks:
    - File must exist.
    - File must not exceed MAX_FILE_SIZE_BYTES.
    - Resolves the path to check for path traversal.

    Inputs:
        file_path: Path to the file to be sent.
    Output:
        Resolved Path object.
    Raises:
        ValueError: If the file path is invalid.
        FileNotFoundError: If the file does not exist.
    """
    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError("File not found.")
    if not path.is_file():
        raise ValueError("Path does not point to a regular file.")
    size = path.stat().st_size
    if size == 0:
        raise ValueError("File is empty.")
    if size > MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"File size ({size} bytes) exceeds limit of {MAX_FILE_SIZE_BYTES} bytes."
        )
    return path


# ─────────────────────────────────────────────
#  Filename Sanitization
# ─────────────────────────────────────────────

def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename received from a peer to prevent path traversal and injection.

    Security:
    - Strips directory components (basename only).
    - Removes null bytes and special characters.
    - Enforces maximum filename length.
    - Rejects reserved Windows filenames.

    Inputs:
        filename: Raw filename received from peer (untrusted).
    Output:
        Safe, sanitized filename string.
    Raises:
        ValueError: If the filename cannot be made safe.
    """
    if not isinstance(filename, str):
        raise ValueError("Filename must be a string.")

    # Extract basename to remove path traversal sequences (e.g., ../../etc/passwd → passwd)
    filename = os.path.basename(filename)

    # Remove null bytes
    filename = filename.replace("\x00", "")

    # Allow only safe characters: alphanumeric, dots, hyphens, underscores
    filename = re.sub(r"[^\w.\-]", "_", filename)

    # Prevent double dots
    filename = re.sub(r"\.{2,}", ".", filename)

    # Enforce length
    if len(filename) > MAX_FILENAME_LENGTH:
        name, ext = os.path.splitext(filename)
        filename = name[: MAX_FILENAME_LENGTH - len(ext)] + ext

    if not filename or filename in {".", ".."}:
        raise ValueError("Filename is invalid after sanitization.")

    # Reject dangerous names
    RESERVED_NAMES = {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3",
    }
    if filename.upper().split(".")[0] in RESERVED_NAMES:
        raise ValueError(f"Reserved filename not allowed: {filename}")

    return filename


# ─────────────────────────────────────────────
#  Integrity Verification
# ─────────────────────────────────────────────

def compute_file_hash(file_path: Path) -> str:
    """
    Compute SHA-256 hash of a file for integrity verification.

    Security:
    - Reads file in chunks to handle large files without loading all into memory.
    - Ensures received files haven't been tampered with during transfer.

    Inputs:
        file_path: Path to the file to hash.
    Output:
        Lowercase hex SHA-256 digest string.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_file_hash(file_path: Path, expected_hash: str) -> bool:
    """
    Verify a file's SHA-256 hash matches the expected value.

    Security:
    - Uses constant-time comparison via hmac.compare_digest to prevent timing attacks.

    Inputs:
        file_path: Path to the file to verify.
        expected_hash: Hex SHA-256 digest to compare against.
    Output:
        True if the hash matches, False otherwise.
    """
    import hmac
    actual = compute_file_hash(file_path)
    return hmac.compare_digest(actual.lower(), expected_hash.lower())


# ─────────────────────────────────────────────
#  Helper Utilities
# ─────────────────────────────────────────────

def _anonymize_id(peer_id: str) -> str:
    """
    Return the first 8 characters of a peer ID for safe log output.

    Security: Prevents full peer addresses from appearing in log files.
    """
    return peer_id[:8] + "..." if len(peer_id) > 8 else peer_id
