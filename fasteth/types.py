"""Types for ethereum data."""
from typing import NewType, Union

# This wraps the ethereum foundation typing.
from eth_typing.abi import Decodable, TypeStr  # noqa: F401
from eth_typing.bls import BLSPubkey, BLSSignature  # noqa: F401
from eth_typing.discovery import NodeID  # noqa: F401
from eth_typing.encoding import HexStr, Primitives  # noqa: F401
from eth_typing.enums import ForkName  # noqa: F401
from eth_typing.ethpm import URI, ContractName, Manifest  # noqa: F401
from eth_typing.evm import (  # noqa: F401
    Address,
    AnyAddress,
    BlockIdentifier,
    BlockNumber,
    ChecksumAddress,
    Hash32,
    HexAddress,
)

# These are used profusely in the API docs as generic HexStr.
# A quantity as a HexStr
Quantity = NewType("Quantity", str)
# A HexStr of data with an arbitrary length
Data = NewType("Data", str)
# A LogsBloom datatype
LogsBloom = NewType("LogsBloom", Data)
# A Signature datatype
Signature = NewType("Signature", Data)
# A block identifier with string support
DefaultBlockIdentifier = Union[str, BlockIdentifier]
