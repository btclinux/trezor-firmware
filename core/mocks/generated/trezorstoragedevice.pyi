from typing import *


# rust/src/storagedevice/storagedevice.rs
def is_version_stored() -> bool:
    """Whether version is in storage."""


# rust/src/storagedevice/storagedevice.rs
def is_initialized() -> bool:
    """Whether device is initialized."""


# rust/src/storagedevice/storagedevice.rs
def get_version() -> bytes:
    """Get version."""


# rust/src/storagedevice/storagedevice.rs
def set_version(version: bytes) -> bool:
    """Set version."""


# rust/src/storagedevice/storagedevice.rs
def get_rotation() -> int:
    """Get rotation."""


# rust/src/storagedevice/storagedevice.rs
def set_rotation(rotation: int) -> bool:
    """Set rotation."""


# rust/src/storagedevice/storagedevice.rs
def get_label() -> str:
    """Get label."""


# rust/src/storagedevice/storagedevice.rs
def set_label(label: str) -> bool:
    """Set label."""


# rust/src/storagedevice/storagedevice.rs
def get_mnemonic_secret() -> bytes:
    """Get mnemonic secret."""


# rust/src/storagedevice/storagedevice.rs
def is_passphrase_enabled() -> bool:
    """Whether passphrase is enabled."""


# rust/src/storagedevice/storagedevice.rs
def set_passphrase_enabled(enable: bool) -> bool:
    """Set whether passphrase is enabled."""


# rust/src/storagedevice/storagedevice.rs
def get_passphrase_always_on_device() -> bool:
    """Whether passphrase is on device."""


# rust/src/storagedevice/storagedevice.rs
def set_passphrase_always_on_device(enable: bool) -> bool:
    """Set whether passphrase is on device."""


# rust/src/storagedevice/storagedevice.rs
def unfinished_backup() -> bool:
    """Whether backup is still in progress."""


# rust/src/storagedevice/storagedevice.rs
def set_unfinished_backup(state: bool) -> bool:
    """Set backup state."""


# rust/src/storagedevice/storagedevice.rs
def needs_backup() -> bool:
    """Whether backup is needed."""


# rust/src/storagedevice/storagedevice.rs
def set_backed_up() -> bool:
    """Signal that backup is finished."""


# rust/src/storagedevice/storagedevice.rs
def no_backup() -> bool:
    """Whether there is no backup."""
