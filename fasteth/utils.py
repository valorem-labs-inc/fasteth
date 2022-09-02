from datetime import datetime
from typing import Any, Dict, Optional

import eth_utils
from eth_utils import add_0x_prefix, conversions  # noqa: F401

from fasteth import types as eth_types

# TODO(consider replacing with enum)
to_py_converters: Dict = {
    eth_types.Hash32: lambda x: eth_utils.to_bytes(None, x),
    eth_types.Address: lambda x: eth_utils.to_bytes(None, x),
    eth_types.HexAddress: eth_utils.to_normalized_address,
    eth_types.ChecksumAddress: eth_utils.to_checksum_address,
    eth_types.AnyAddress: lambda x: eth_utils.to_bytes(None, x),
    eth_types.HexStr: lambda x: eth_utils.to_text(None, x),
    eth_types.BlockNumber: lambda x: eth_utils.to_int(None, x),
    eth_types.BlockIdentifier: lambda x: eth_utils.to_int(None, x),
    eth_types.Data: lambda x: eth_utils.to_text(None, x),
    datetime: lambda x: datetime.fromtimestamp(eth_utils.to_int(None, x)),
    int: lambda x: eth_utils.to_int(None, x),
    str: lambda x: eth_utils.to_text(None, None, x),
    bytes: lambda x: eth_utils.to_bytes(None, x),
    Optional[eth_types.Hash32]: lambda x: eth_utils.to_bytes(None, x),
    Optional[eth_types.Address]: lambda x: eth_utils.to_bytes(None, x),
    Optional[eth_types.HexAddress]: eth_utils.to_normalized_address,
    Optional[eth_types.ChecksumAddress]: eth_utils.to_checksum_address,
    Optional[eth_types.AnyAddress]: lambda x: eth_utils.to_bytes(None, x),
    Optional[eth_types.HexStr]: lambda x: eth_utils.to_text(None, x),
    Optional[eth_types.BlockNumber]: lambda x: eth_utils.to_int(None, x),
    Optional[eth_types.BlockIdentifier]: lambda x: eth_utils.to_int(None, x),
    Optional[eth_types.Data]: lambda x: eth_utils.to_text(None, x),
    Optional[datetime]: lambda x: datetime.fromtimestamp(eth_utils.to_int(None, x)),
    Optional[int]: lambda x: eth_utils.to_int(None, x),
    Optional[str]: lambda x: eth_utils.to_text(None, None, x),
    Optional[bytes]: lambda x: eth_utils.to_bytes(None, x),
}

to_eth_converters: Dict = {
    eth_types.Hash32: eth_utils.to_hex,
    eth_types.Address: eth_utils.to_hex,
    eth_types.HexAddress: eth_utils.to_normalized_address,
    eth_types.ChecksumAddress: eth_utils.to_checksum_address,
    eth_types.AnyAddress: eth_utils.to_hex,
    eth_types.HexStr: lambda x: eth_utils.to_hex(None, None, x),
    eth_types.BlockNumber: eth_utils.to_hex,
    eth_types.BlockIdentifier: eth_utils.to_hex,
    eth_types.Data: lambda x: eth_utils.to_hex(None, None, x),
    datetime: lambda x: eth_utils.to_hex(x.timestamp()),
    int: eth_utils.to_hex,
    str: lambda x: eth_utils.to_hex(None, None, x),
    bytes: eth_utils.to_hex,
    Optional[eth_types.Hash32]: eth_utils.to_hex,
    Optional[eth_types.Address]: eth_utils.to_hex,
    Optional[eth_types.HexAddress]: eth_utils.to_normalized_address,
    Optional[eth_types.ChecksumAddress]: eth_utils.to_checksum_address,
    Optional[eth_types.AnyAddress]: eth_utils.to_hex,
    Optional[eth_types.HexStr]: lambda x: eth_utils.to_hex(None, None, x),
    Optional[eth_types.BlockNumber]: eth_utils.to_hex,
    Optional[eth_types.BlockIdentifier]: eth_utils.to_hex,
    Optional[eth_types.Data]: lambda x: eth_utils.to_hex(None, None, x),
    Optional[datetime]: lambda x: eth_utils.to_hex(x.timestamp()),
    Optional[int]: eth_utils.to_hex,
    Optional[str]: lambda x: eth_utils.to_hex(None, None, x),
    Optional[bytes]: eth_utils.to_hex,
}


def result_truthiness(result: str) -> Any:
    """Parse string to bool, or if there is no bool, return the original."""
    if type(result) == str:
        # Results for True/False sometimes return as string.
        if result == "False":
            return False
        elif result == "True":
            return True
        else:
            return result
    return result
