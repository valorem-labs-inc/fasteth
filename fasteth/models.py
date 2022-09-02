"""Dataclasses for fasteth data types."""
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, ClassVar, Dict, List, Optional, Type, TypeVar, Union

from pydantic import BaseModel, Field

from fasteth import exceptions as eth_exp
from fasteth import types as eth_types
from fasteth import utils


class Network(int, Enum):
    """An enum representing the ethereum network id."""

    Mainnet = 1
    Morden = 2
    Ropsten = 3
    Rinkeby = 4
    Kovan = 42
    Ganache = 1337


class RPCSchema(tuple, Enum):
    """An enum representing method and id mappings."""

    client_version = ("web3_clientVersion", 67)
    sha3 = ("web3_sha3", 64)
    network_version = ("net_version", 67)
    network_listening = ("net_listening", 67)
    network_peer_count = ("net_peerCount", 74)
    protocol_version = ("eth_protocolVersion", 67)
    syncing = ("eth_syncing", 1)
    coinbase = ("eth_coinbase", 64)
    mining = ("eth_mining", 71)
    hashrate = ("eth_hashrate", 71)
    gas_price = ("eth_gasPrice", 73)
    accounts = ("eth_accounts", 1)
    block_number = ("eth_blockNumber", 83)
    get_balance = ("eth_getBalance", 1)
    get_storage_at = ("eth_getStorageAt", 1)
    get_transaction_count = ("eth_getTransactionCount", 1)
    get_block_by_number = ("eth_getBlockByNumber", 1)
    get_block_by_hash = ("eth_getBlockByHash", 1)
    get_block_transaction_count_by_hash = ("eth_getBlockTransactionCountByHash", 1)
    get_block_transaction_count_by_number = ("eth_getBlockTransactionCountByNumber", 1)
    get_uncle_count_by_block_hash = ("eth_getUncleCountByBlockHash", 1)
    get_uncle_count_by_block_number = ("eth_getUncleCountByBlockNumber", 1)
    get_shh_messages = ("shh_getMessages", 73)
    get_shh_filter_changes = ("shh_getFilterChanges", 73)
    get_code = ("eth_getCode", 1)
    submit_hashrate = ("eth_submitHashrate", 73)
    sign = ("eth_sign", 1)
    sign_transaction = ("eth_signTransaction", 1)
    send_transaction = ("eth_sendTransaction", 1)
    send_raw_transaction = ("eth_sendRawTransaction", 1337)
    call = ("eth_call", 1)
    estimate_gas = ("eth_estimateGas", 1)
    shh_version = ("shh_version", 73)
    shh_post = ("shh_post", 73)
    shh_new_identity = ("shh_newIdentity", 73)
    shh_has_identity = ("shh_hasIdentity", 73)
    shh_new_group = ("shh_newGroup", 73)
    shh_add_to_group = ("shh_addToGroup", 73)
    shh_new_filter = ("shh_newFilter", 73)
    shh_uninstall_filter = ("shh_uninstallFilter", 73)


class Ethable(ABC, BaseModel):
    """Abstract base class for classes presenting an explicit conversion for eth RPC
    """

    @abstractmethod
    def dict(self) -> Dict:
        """Returns a dict for submission in an RPC request.

        :returns
            dict: The RPC request data.
        """
        pass

    @staticmethod
    @abstractmethod
    def parse_obj(data: Dict) -> Any:
        """Returns the data decoded to this type."""
        pass


# Create a generic variable that can be 'AutoEthable', or any subclass.
T = TypeVar("T", bound=Ethable)
FROM_KEY = "from_address"
FROM = "from"


def iterate_list(model_type: Type[T], data: List):
    """Returns the elements of the data converted to model_type in a new list."""
    return [model_type.parse_obj(v) for v in data]


class AutoEthable(Ethable):
    """Provides encode and decode functionality without explicit conversion.

    Using AutoEthable vs declaring explicit dict and parse_obj methods incurs
    a 30% overhead overall, and a ~2x overhead in the inter-quartile range.

    Use with that in mind.
    """

    def dict(self: Type[T]) -> Dict:
        """Returns a dict for submission in an RPC request.

        :returns
            dict: The RPC request data.
        """
        # Dictionary for eth RPC Request JSON
        r: Dict = {}

        for k, t in self.__annotations__.items():
            v = getattr(self, k)
            # Workaround python built-in
            if v is None:
                continue

            if k == FROM_KEY:
                r[FROM] = v
                k = FROM

            if t in utils.to_eth_converters:
                # Check if this is a simple type with a converter.
                r[k] = utils.to_eth_converters[t](v)
            elif issubclass(type(t), Ethable):
                r[k] = t.dict(v)
            elif hasattr(t, "__args__") and t == List[t.__args__[0]]:  # type: ignore
                if t.__args__[0] in utils.to_eth_converters:
                    # Map the converter to each member of the list
                    r[k] = [utils.to_eth_converters[t.__args__[0]](x) for x in v]
                elif issubclass(t.__args__[0], Ethable):
                    # This is an ethable type, recurse encoder.
                    r[k] = [t.__args__[0].dict(x) for x in v]
            else:
                r[k] = v

        return r

    @classmethod
    def parse_obj(cls: Type[T], data: Dict) -> T:
        """Returns python typed object from ethereum typed object.

        This will mutate data, so used data.copy() to avoid as needed.
        TODO(consider making this input not mutate, it's bug prone)

        :type data: dict
        :param data: The dictionary of data to populate the dataclass with.
        """
        if FROM in data:
            data[FROM_KEY] = data.pop(FROM)

        for k, t in cls.__annotations__.items():
            # We only need to access the value once.
            v = data.get(k)

            if v is None:
                # Then this is either an optional or non-existent value in input.
                continue

            if t in utils.to_py_converters:
                # Check if the type has an eth encoder, encode if so.
                data[k] = utils.to_py_converters[t](v)
            elif issubclass(type(t), Ethable):
                data[k] = t.parse_obj(v)
            elif hasattr(t, "__args__") and t == List[t.__args__[0]]:  # type: ignore
                # A list of non-Ethable types.
                if t.__args__[0] in utils.to_py_converters:
                    # Map the converter to each member of the list
                    data[k] = [utils.to_py_converters[t.__args__[0]](x) for x in v]
                elif issubclass(t.__args__[0], Ethable):
                    # This is an ethable type, recurse decoder.
                    data[k] = [t.__args__[0].parse_obj(x) for x in v]
            else:
                data[k] = v

        return cls(**data)


# noinspection PyUnresolvedReferences
class JSONRPCRequest(BaseModel):
    """Model for JSON RPC Request.

    Attributes:
        jsonrpc: A String specifying the version of the JSON-RPC protocol.
                 MUST be exactly "2.0".
        method: A String containing the name of the method to be invoked. Method names
                that begin with the word rpc followed by a period character
                (U+002E or ASCII 46) are reserved for rpc-internal methods and
                extensions and MUST NOT be used for anything else.
        params: A Structured value that holds the parameter values to be used during
                the invocation of the method. This member MAY be omitted.
        id: An identifier established by the Client that MUST contain a String, Number,
            or None value if included. If it is not included it is assumed to be a
            notification. The value SHOULD normally not be None and Numbers
            SHOULD NOT contain fractional parts.

    The Server MUST reply with the same value in the Response object if included.
    This member is used to correlate the context between the two objects.

    The use of None as a value for the id member in a Request object is discouraged,
    because this specification uses a value of None for Responses with an unknown id.
    Also, because JSON-RPC 1.0 uses an id value of Null for Notifications this could
    cause confusion in handling.

    Fractional parts may be problematic, since many decimal fractions cannot be
    represented exactly as binary fractions.
    """

    jsonrpc: str = "2.0"
    method: str
    params: List = Field(default_factory=list)
    id: int


class EthereumErrorData(BaseModel):
    # TODO(Break out handling logic here.)
    code: int
    message: str


# noinspection PyUnresolvedReferences
class JSONRPCErrorData(BaseModel):
    """RPC Call Error Model.

    Attributes:
        code: A Number that indicates the error type that occurred.
              This MUST be an integer.
        message: A String providing a short description of the error.
                 The message SHOULD be limited to a concise single sentence.
        data: A Primitive or Structured value that contains additional information
              about the error. This may be omitted. The value of this member is
              defined by the Server (e.g. detailed error information, nested
              errors etc.).

    The error codes from and including -32768 to -32000 are reserved for
    pre-defined errors. Any code within this range, but not defined explicitly
    below is reserved for future use. The error codes are nearly the same as those
    suggested for XML-RPC at the following url:
    http://xmlrpc-epi.sourceforge.net/specs/rfc.fault_codes.php

    code 	message 	        meaning
    -32700 	Parse error 	    Invalid JSON was received by the server.
                                An error occurred on the server while parsing
                                the JSON text.
    -32600 	Invalid Request 	The JSON sent is not a valid Request object.
    -32601 	Method not found 	The method does not exist / is not available.
    -32602 	Invalid params 	    Invalid method parameter(s).
    -32603 	Internal error 	    Internal JSON-RPC error.
    -32000
    to
    -32099 	Server error 	    Reserved for implementation-defined server-errors.

    The remainder of the space is available for application defined errors.
    """

    code: int
    message: str
    data: Optional[Union[Dict, List, List[EthereumErrorData]]]
    _exp: ClassVar = {
        -32700: eth_exp.ParseError,
        -32600: eth_exp.InvalidRequest,
        -32601: eth_exp.MethodNotFound,
        -32602: eth_exp.InvalidParams,
        -32603: eth_exp.InternalError,
        1: eth_exp.UnauthorizedError,
        2: eth_exp.ActionNotAllowed,
    }
    _eth_error: ClassVar = {
        100: eth_exp.NotFound,
        101: eth_exp.RequiresEther,
        102: eth_exp.GasTooLow,
        103: eth_exp.GasLimitExceeded,
        104: eth_exp.Rejected,
        105: eth_exp.EtherTooLow,
    }

    def raise_for_error(self):
        if self.code in self._exp:
            if self.code == 3:
                # TODO(Consider raising multiple exceptions here for each error
                #  in the list of errors)
                for elem in self.data:
                    raise self._eth_error[elem.code](elem.message)
            else:
                raise self._exp[self.code](self.message)
        elif self.code in range(-32099, -32000):
            raise eth_exp.ServerError
        else:
            # Raise the generic error.
            raise eth_exp.JSONRPCError


# noinspection PyUnresolvedReferences
class JSONRPCResponse(BaseModel):
    """Model for JSON RPC response.

    Attributes:
        id:  This member is REQUIRED. It MUST be the same as the value of the id
             member in the JSONRPCRequest Object. If there was an error in detecting
             the id in the Request object (e.g. Parse error/Invalid Request), it MUST
             be None.
        jsonrpc: A String specifying the version of the JSON-RPC protocol.
                 MUST be exactly "2.0".
        result: This member is REQUIRED on success. This member MUST NOT exist if
                there was an error invoking the method. The value of this member is
                determined by the method invoked on the Server.
        error: This member is REQUIRED on error. This member MUST NOT exist if
               there was no error triggered during invocation. The value for this
               member MUST be an Object.
        # TODO(Add result and error types according to json rpc spec)
        # https://www.jsonrpc.org/specification
    """

    id: Optional[int] = None
    jsonrpc: str = "2.0"
    error: Optional[JSONRPCErrorData] = None
    result: Optional[Union[Dict, List, eth_types.HexStr, bool]] = None


# noinspection PyUnresolvedReferences
class SyncStatus(AutoEthable):
    """Model representing node sync status.

    Attributes:
        startingBlock (int): The starting block for the sync in progress.
        currentBlock (int): The current block for the sync in progress.
        currentBlock (int): The current block for the sync in progress.
    """

    startingBlock: Optional[int] = None
    currentBlock: Optional[int] = None
    highestBlock: Optional[int] = None
    syncing: bool = False


# noinspection PyUnresolvedReferences
class Transaction(AutoEthable):
    """The transaction object.

    Attributes:
        from_address (eth_types.Address): The address the transaction is sent from. This
                                          is sent to the RPC as 'from'.
        to (eth_types.Address): (optional when creating new contract) The address the
                                transaction is directed to.
        gas (int): Integer of the gas provided for the transaction. It will return
                   unused gas.
        gasPrice (int): Integer of the gasPrice used for each paid gas, in Wei.
        value (int): Integer of the value sent with this transaction, in Wei.
        data (eth_types.Data): The compiled code of a contract OR the hash of the
                               invoked method signature and encoded parameters. See
                               the Ethereum Contract ABI specification for more detail.
        nonce (int): This allows to overwrite your own pending transactions that use
                     the same nonce.

    """

    from_address: eth_types.HexAddress
    data: Optional[eth_types.Data] = None
    to: Optional[eth_types.HexAddress] = None
    gas: Optional[int] = None
    gasPrice: Optional[int] = None
    value: Optional[int] = None
    nonce: Optional[int] = None
    hash: Optional[eth_types.Hash32] = None
    input: Optional[bytes] = None
    transactionIndex: Optional[int] = None
    blockHash: Optional[eth_types.Hash32] = None
    blockNumber: Optional[int] = None
    type: Optional[int] = None  # This is not in the spec but exists in the return
    v: Optional[int] = None
    r: Optional[eth_types.Signature] = None
    s: Optional[eth_types.Signature] = None


class Block(AutoEthable):
    # noinspection PyUnresolvedReferences
    """The block object.

    Attributes:
        number (int): The block number. None when its pending block.
        hash (Union[eth_types.Hash32, None]): 32 Bytes - hash of the block.
                                              None when its pending block.
        parentHash (eth_types.Hash32): 32 Bytes - hash of the parent block.
        nonce (Union[eth_types.Data, None]): 8 Bytes - hash of the generated
                                             proof-of-work. None when its pending block.
        sha3Uncles (eth_types.Hash32): 32 Bytes - SHA3 of the uncles data in the
                                     block.
        logsBloom (eth_types.LogsBloom): 256 Bytes - the bloom filter for the logs
                                         of the block. null when its pending block.
        transactionsRoot (eth_types.Hash32): 32 Bytes - the root of the transaction
                                             trie of the block.
        stateRoot (eth_types.Hash32): 32 Bytes - the root of the final state trie
                                      of the block.
        receiptsRoot (eth_types.Hash32): 32 Bytes - the root of the receipts trie of
                                         the block.
        miner (eth_types.Address): 20 Bytes - the address of the beneficiary to
                                   whom the mining rewards were given.
        difficulty (int): The difficulty for this block.
        totalDifficulty (int): The total difficulty of the chain until this block.
        extraData (eth_types.Data): The “extra data” field of this block.
        size (int): The size of this block in bytes.
        gasLimit (int): The maximum gas allowed in this block.
        gasUsed (int): The total used gas by all transactions in this block.
        timestamp (Arrow): Time for when the block was collated.
        transactions (List[Union[Transaction, eth_types.Hash32]): List of transaction
            objects, or 32 Bytes transaction hashes depending on the last given
            parameter.
        uncles (List[eth_types.Hash32]): List of uncle hashes.
    """

    logsBloom: Optional[eth_types.LogsBloom] = None
    number: Optional[int] = None
    hash: Optional[eth_types.Hash32] = None
    nonce: Optional[int] = None
    parentHash: eth_types.Hash32
    sha3Uncles: eth_types.Hash32
    mixHash: eth_types.Hash32
    transactionsRoot: eth_types.Hash32
    stateRoot: eth_types.Hash32
    receiptsRoot: eth_types.Hash32
    miner: eth_types.Address
    difficulty: int
    totalDifficulty: int
    extraData: str
    size: int
    gasLimit: int
    gasUsed: int
    timestamp: datetime
    uncles: List[eth_types.Hash32]
    transactions: List[Transaction] = Field(default_factory=list)


class WhisperFilter(AutoEthable):
    # noinspection PyUnresolvedReferences
    """Creates filter to notify, when client receives whisper message
    matching the filter options.

    Attributes:
        to (eth_types.Address): Identity of the receiver. When
            present it will try to decrypt any incoming message if the
            client holds the private key to this identity.
        topics (list[eth_types.Data]): Array of DATA topics which the incoming
                message’s topics should match. You can use the following
                combinations:
                    [A, B] = A && B
                    [A, [B, C]] = A && (B || C)
                    [null, A, B] = ANYTHING && A && B null works as a wildcard
    """

    to: eth_types.HexAddress
    topics: list[eth_types.Data]


class Message(AutoEthable):
    # noinspection PyUnresolvedReferences
    """Whisper Message.

    Attributes:
        hash (eth_types.Data): The hash of the message.
        from (eth_types.Address): The sender of the message, if specified.
        to (eth_types.Address): The receiver of the message, if specified.
        expiry (int): Time in seconds when this message should expire.
        ttl (int): Time the message should float in the system in seconds.
        sent (int): The unix timestamp when the message was sent.
        topics (list[eth_types.Data]): Topics the message contained.
        payload (eth_types.Data): The payload of the message.
        workProved (int): The work this message required before it was send.
    """

    topics: list[eth_types.Data]
    payload: eth_types.Data
    ttl: int
    priority: int = 1
    from_address: Optional[eth_types.HexAddress] = None
    to: Optional[eth_types.HexAddress] = None
    workProved: Optional[int] = None
    sent: Optional[int] = None
    expiry: Optional[int] = None
    message_hash: Optional[eth_types.Hash32] = None
