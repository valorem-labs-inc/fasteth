# 3rd party imports
from typing import Any, List, Optional, Union

# noinspection PyPackageRequirements
import httpx
import orjson
from eth_utils import conversions

from fasteth import models as eth_models
from fasteth import types as eth_types
from fasteth import utils as eth_utils

# TODO(Websocket support)
# TODO(IPC Support)
# TODO(Add doc about https://eth.wiki/json-rpc/API#the-default-block-parameter)
# TODO(Consider this: https://github.com/ethereum/snake-charmers-tactical-manual)
# Reminder, use decimal.Decimal for any math involving 2 integers becoming a float.
# That is the python style guide for ethereum projects.
# See https://docs.soliditylang.org/en/latest/abi-spec.html

# pile of "magic" variables to deal with.
# TODO(move these out of the module scope)
default_block_id: eth_types.DefaultBlockIdentifier = "latest"
position_zero: eth_types.Data = eth_utils.to_eth_converters[eth_types.Data]("0x0")
result_key = "result"
localhost = "http://localhost:8545/"
json_headers = {"Content-Type": "application/json"}


class AsyncJSONRPCCore(httpx.AsyncClient):
    """Asynchronous remote procedure call client."""

    def __init__(self, rpc_uri: str = localhost, http2: bool = False):
        """Initialize JSON RPC.

        :param rpc_uri: RPC URI for ethereum client.
        :param http2: Boolean to use http2 when true.
        """
        super().__init__(http2=http2)
        self.rpc_uri = rpc_uri

    async def rpc(self, rpc_request: eth_models.JSONRPCRequest) -> Any:
        """Return JSONRPCResponse for the JSONRPCRequest, executing a RPC.

        :raises eth_exceptions.JSONRPCError
        :raises httpx.HTTPStatusError
        :raises httpx.StreamError"""
        response = await self.post(
            url=self.rpc_uri,
            headers=json_headers,
            content=orjson.dumps(rpc_request.dict()),
        )
        # We want to raise here http errors.
        response.raise_for_status()
        # Now we get back the JSON and do error handling.
        rpc_response = eth_models.JSONRPCResponse.parse_obj(
            orjson.loads(response.content)
        )
        if rpc_response.error:
            rpc_response.error.raise_for_error()
        return rpc_response.result


class AsyncEthereumJSONRPC(AsyncJSONRPCCore):
    """Presents an asynchronous interface to the ethereum JSON RPC.

    This class aggressively converts the strings returned in result
    bodies into efficient native python data eth_types in cases where a string
    is returned in place of an int, et cētera.

    The API info at https://eth.wiki/json-rpc/API was highly helpful in
    creating this.
    """

    rpc_schema = eth_models.RPCSchema

    async def client_version(self) -> str:
        """Return the current ethereum client version as a string.

        Calls web3_clientVersion

        :returns
            string: The current client version.
        """
        return await self.rpc(
            eth_models.JSONRPCRequest(
                method=self.rpc_schema.client_version[0],
                id=self.rpc_schema.client_version[1],
            )
        )

    async def sha3(self, data: eth_types.Data) -> eth_types.Data:
        """Returns the Keccak-256 of the given data.

        Consider using eth_utils.sha3 instead to save the round trip.

        :param data: Bytes of eth_types.Data to Keccak-256 hash.

        :returns
            eth_types.Data: Keccak-256 bytes of eth_types.Data
        """
        return eth_utils.to_py_converters[eth_types.Hash32](
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.sha3[0],
                    id=self.rpc_schema.sha3[1],
                    params=[eth_utils.to_eth_converters[eth_types.Data](data)],
                )
            )
        )

    async def network_version(self) -> eth_models.Network:
        """Returns the current network ID.

        Calls net_version.

        :returns
            Network:Enum populated with network ID.
        """
        # noinspection PyArgumentList
        # PyCharm is incorrect here.
        return eth_models.Network(
            int(
                await self.rpc(
                    eth_models.JSONRPCRequest(
                        method=self.rpc_schema.network_version[0],
                        id=self.rpc_schema.network_version[1],
                    )
                )
            )
        )

    async def network_listening(self) -> bool:
        """Returns true if client is actively listening for network connections.

        Calls net_listening.

        :returns
            bool: True when listening, otherwise False"""
        return await self.rpc(
            eth_models.JSONRPCRequest(
                method=self.rpc_schema.network_listening[0],
                id=self.rpc_schema.network_listening[1],
            )
        )

    async def network_peer_count(self) -> int:
        """Returns number of peers currently connected to the client

        Calls net_peerCount.

        :returns
            int: number of connected peers
        """
        return eth_utils.to_py_converters[int](
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.network_peer_count[0],
                    id=self.rpc_schema.network_peer_count[1],
                )
            )
        )

    async def protocol_version(self) -> int:
        """Returns the current ethereum protocol version.

        Calls eth_protocolVersion.

        :returns
            int: The current Ethereum protocol version as an Integer."""
        return eth_utils.to_py_converters[int](
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.protocol_version[0],
                    id=self.rpc_schema.protocol_version[1],
                )
            )
        )

    async def syncing(self) -> eth_models.SyncStatus:
        """Returns an object with sync status data.

        Calls eth_syncing.

        :returns
            eth_models.SyncStatus or False: with sync status data or False when
                                               not syncing.
        """
        # It mystifies me why this can't return a proper JSON boolean.
        result = eth_utils.result_truthiness(
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.syncing[0], id=self.rpc_schema.syncing[1]
                )
            )
        )

        if result:
            result["syncing"] = True
            return eth_models.SyncStatus.parse_obj(result)
        else:
            return eth_models.SyncStatus(syncing=False)

    async def coinbase(self) -> eth_types.HexAddress:
        """Returns the client coinbase address

        Calls eth_coinbase.

        :returns
            str:The current coinbase address.
        :raises
           :exception JSONRPCError: when this method is not supported.
        """
        return eth_types.HexAddress(
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.coinbase[0], id=self.rpc_schema.coinbase[1]
                )
            )
        )

    async def mining(self) -> bool:
        """Returns True if the client is actively mining new blocks.

        Calls eth_mining.

        :returns
            bool: True if the client is mining, otherwise False
        """
        # Why can this RPC actually return a bool?
        return eth_utils.result_truthiness(
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.mining[0], id=self.rpc_schema.mining[1]
                )
            )
        )

    async def hashrate(self) -> int:
        """Returns the number of hashes per second that the node is mining with.

        Calls eth_hashrate.

        :returns:
            int:Number of hashes per second.
        """
        return eth_utils.to_py_converters[int](
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.hashrate[0], id=self.rpc_schema.mining[1]
                )
            )
        )

    async def gas_price(self) -> int:
        """Returns the current gas price as an integer in wei.

        Calls eth_gasPrice.

        :returns
            int:integer of the current gas price in wei.
        """
        return eth_utils.to_py_converters[int](
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.gas_price[0], id=self.rpc_schema.gas_price[1]
                )
            )
        )

    async def accounts(self) -> list[eth_types.HexAddress]:
        """Returns a list of addresses owned by the client.

        Calls eth_accounts.

        :returns
            list: A list of eth_types.Address owned by the client.
        """
        result = await self.rpc(
            eth_models.JSONRPCRequest(
                method=self.rpc_schema.accounts[0], id=self.rpc_schema.accounts[1]
            )
        )

        return result or []

    async def block_number(self) -> int:
        """Returns the number of most recent block.

        Calls eth_blockNumber.

        :returns
            eth_types.BlockNumber: The current block number a client is on as an int.
        """
        return eth_utils.to_py_converters[int](
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.block_number[0],
                    id=self.rpc_schema.block_number[1],
                )
            )
        )

    async def get_balance(
        self,
        address: eth_types.HexAddress,
        block_identifier: eth_types.DefaultBlockIdentifier = default_block_id,
    ) -> int:
        """Returns the balance of the given address during the given block block_number.

        Calls eth_getBalance.

        :param address: an ethereum address to get the balance of.
        :param block_identifier: an eth_types.DefaultBlockIdentifier of the block
                                 number to check at.

        :returns
            int: The balance in wei during block_number.
        """
        return eth_utils.to_py_converters[int](
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.get_balance[0],
                    id=self.rpc_schema.get_balance[1],
                    params=[address, block_identifier],
                )
            )
        )

    async def get_storage_at(
        self,
        address: eth_types.HexAddress,
        position: int = 0,
        block_identifier: eth_types.DefaultBlockIdentifier = default_block_id,
    ) -> eth_types.Data:
        """Returns storage from position at a given address during block_identifier.

        Calls eth_getStorageAt.

        See: https://eth.wiki/json-rpc/API#eth_getstorageat

        There are some usage examples at that link which are useful.

        eth_utils.keccak and eth-hash are useful here as well.

        :param address: eth_types.Address address of the storage.
        :param position: integer as eth_types.Data of the position in the storage.
        :param block_identifier: eth_types.DefaultBlockIdentifier for the block to
                                 retrieve from.

        :returns eth_types.Data: containing the data at the address, position,
                                 block_identifier.
        """
        return eth_utils.to_py_converters[eth_types.Data](
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.get_storage_at[0],
                    id=self.rpc_schema.get_storage_at[1],
                    params=[
                        address,
                        eth_utils.to_eth_converters[int](position),
                        block_identifier,
                    ],
                )
            )
        )

    async def get_transaction_count(
        self,
        address: eth_types.HexAddress,
        block_identifier: eth_types.DefaultBlockIdentifier = default_block_id,
    ) -> int:
        """Returns the number of transactions sent from an address.

        Calls eth_getTransactionCount

        :param address: address to get count for.
        :param block_identifier: eth_types.DefaultBlockIdentifier to get count at.

        :returns int: The number of transactions sent from address.
        """
        return eth_utils.to_py_converters[int](
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.get_transaction_count[0],
                    id=self.rpc_schema.get_transaction_count[1],
                    params=[address, block_identifier],
                )
            )
        )

    # TODO(conversion from block number to hash)
    async def get_block_transaction_count_by_hash(
        self, block_hash: eth_types.Hash32
    ) -> int:
        """Returns the number of txns in a block matching the given block_hash.

        Calls eth_getBlockTransactionCountByHash.

        Can raise an exception converting integer if block_hash is is invalid.

        :param block_hash: eth_types.Hash32 of the block.

        :returns
            int: Transaction count for given block.
        """
        return eth_utils.to_py_converters[int](
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.get_block_transaction_count_by_hash[0],
                    id=self.rpc_schema.get_block_transaction_count_by_hash[1],
                    params=[eth_utils.to_eth_converters[eth_types.Hash32](block_hash)],
                )
            )
        )

    async def get_block_transaction_count_by_number(
        self, block_identifier: eth_types.DefaultBlockIdentifier
    ) -> int:
        """Returns the number of txns in a block matching the given block_identifier.

        Calls eth_getBlockTransactionCountByNumber.

        Can raise an exception converting integer if block_identifier is is invalid.

        :param block_identifier: eth_types.DefaultBlockIdentifier of the block.

        :returns
            int: Transaction count for given block.
        """
        return eth_utils.to_py_converters[int](
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.get_block_transaction_count_by_number[0],
                    id=self.rpc_schema.get_block_transaction_count_by_number[1],
                    params=[block_identifier],
                )
            )
        )

    async def get_uncle_count_by_block_hash(self, block_hash: eth_types.Hash32) -> int:
        """Returns the number of uncles from a block matching the given block_hash.

        Calls eth_getUncleCountByBlockHash.

        Can raise an exception converting integer if block_hash is is invalid.

        :param block_hash: eth_types.HexAddress hash of the block.

        :returns
            int: number of uncles in this block.
        """
        return eth_utils.conversions.to_int(
            hexstr=await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.get_uncle_count_by_block_hash[0],
                    id=self.rpc_schema.get_uncle_count_by_block_hash[1],
                    params=[eth_utils.to_eth_converters[eth_types.Hash32](block_hash)],
                )
            )
        )

    async def get_uncle_count_by_block_number(
        self, block_identifier: eth_types.DefaultBlockIdentifier
    ) -> int:
        """Returns the number of uncles block matching the given block_identifier.

        Calls eth_getUncleCountByBlockNumber.

        Can raise an exception converting integer if block_identifier is is invalid.

        :param block_identifier: eth_types.DefaultBlockIdentifier of the block.

        :returns
            int: number of uncles in this block.
        """
        return eth_utils.conversions.to_int(
            hexstr=await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.get_uncle_count_by_block_number[0],
                    id=self.rpc_schema.get_uncle_count_by_block_number[1],
                    params=[block_identifier],
                )
            )
        )

    async def get_code(
        self,
        address: eth_types.HexAddress,
        block_identifier: eth_types.DefaultBlockIdentifier = default_block_id,
    ) -> eth_types.Data:
        """Return code at a given address during specified block.

        :param address: The address to retrieve the code from.
        :param block_identifier: the block during which to get the code from.

        :returns
            eth_types.HexStr: string in hex format containing the code as data.
        """
        return eth_utils.to_py_converters[eth_types.Data](
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.get_code[0],
                    id=self.rpc_schema.get_code[1],
                    params=[address, block_identifier],
                )
            )
        )

    async def sign(
        self, address: eth_types.HexAddress, message: eth_types.HexStr
    ) -> eth_types.Data:
        """Returns an signed message.

        sign(keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)))

        By adding a prefix to the message makes the calculated signature recognizable
        as an Ethereum specific signature. This prevents misuse where a malicious
        DApp can sign arbitrary data (e.g. transaction) and use the signature to
        impersonate the victim.

        Note the address to sign with must be unlocked.

        Calls eth_sign.

        TODO(Add tests for this function)

        :param address: address to sign with.
        :param message: hex string of n bytes, message to sign.

        :returns
            eth_types.Data: signature
        """
        return await self.rpc(
            eth_models.JSONRPCRequest(
                method=self.rpc_schema.sign[0],
                id=self.rpc_schema.sign[1],
                params=[address, message],
            )
        )

    async def sign_transaction(
        self, transaction: eth_models.Transaction
    ) -> eth_types.HexStr:
        """Returns a signed transaction object as eth_types.HexStr.

        Signs and returns a transaction that can be submitted to the network at a
        later time using with send_raw_transaction.

        Calls eth_signTransaction

        :param transaction: eth_models.Transaction object to sign.

        :returns
           eth_types.HexStr: The signed transaction object.
        """
        return await self.rpc(
            eth_models.JSONRPCRequest(
                method=self.rpc_schema.sign_transaction[0],
                id=self.rpc_schema.sign_transaction[1],
                params=[transaction.dict()],
            )
        )

    async def send_transaction(
        self, transaction: eth_models.Transaction
    ) -> eth_types.HexStr:
        """Creates new message call transaction or a contract creation.

        :param transaction: eth_models.Transaction object to send.

        :returns
           eth_types.HexStr: the transaction hash, or the zero hash if the transaction
                             is not yet available.
        """

        return eth_types.HexStr(
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.send_transaction[0],
                    id=self.rpc_schema.send_transaction[1],
                    params=[transaction.dict()],
                )
            )
        )

    async def send_raw_transaction(self, data: eth_types.HexStr) -> eth_types.HexStr:
        """Creates new transaction or a contract creation for signed transactions.

        # TODO(Handle reverted execution)

        :param data: The signed transaction data.

        :returns
           eth_types.HexStr: the transaction hash, or the zero hash if the transaction
                             is not yet available.
        """
        return eth_types.HexStr(
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.send_raw_transaction[0],
                    id=self.rpc_schema.send_raw_transaction[1],
                    params=[data],
                )
            )
        )

    async def call(
        self,
        transaction: eth_models.Transaction,
        block_identifier: eth_types.DefaultBlockIdentifier,
    ) -> eth_types.HexStr:
        """Execute a new message call without creating a new block chain transaction.

        Calls eth_call.

        :param transaction: eth_models.Transaction call object.
        :param block_identifier: block to call the transaction against.

        :returns
           eth_types.data: The return value of executed contract.
        """
        return await self.rpc(
            eth_models.JSONRPCRequest(
                method=self.rpc_schema.call[0],
                id=self.rpc_schema.call[1],
                params=[transaction.dict(), block_identifier],
            )
        )

    async def estimate_gas(
        self,
        transaction: eth_models.Transaction,
        block_identifier: eth_types.DefaultBlockIdentifier,
    ) -> int:
        """Returns an estimate of how much gas is necessary to complete the transaction.

        Generates and returns an estimate of how much gas is necessary to allow the
        transaction to complete. The transaction will not be added to the blockchain.
        Note that the estimate may be significantly more than the amount of gas
        actually used by the transaction, for a variety of reasons including EVM
        mechanics and node performance.

        Calls eth_estimateGas.

        :param transaction: eth_models.Transaction call object.
        :param block_identifier: block to call the transaction against.

        :returns
           int: The amount of gas used.
        """
        ret: int = eth_utils.to_py_converters[int](
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.estimate_gas[0],
                    id=self.rpc_schema.estimate_gas[1],
                    params=[transaction.dict(), block_identifier],
                )
            )
        )
        return ret

    async def get_block_by_hash(
        self, block_id: eth_types.Hash32, full: bool = False,
    ) -> Optional[eth_models.Block]:
        """Returns information about a block by hash.

        Calls the eth_getBlockByHash.

        :param block_id: eth_types.Hash32 of a block.
        :param full: If True it returns the full transaction objects, if False
                     only the hashes of the transactions.

        :returns
            Union[eth_models.Block, None]: A block object, or None when no block found.
        """
        data = await self.rpc(
            eth_models.JSONRPCRequest(
                method=self.rpc_schema.get_block_by_hash[0],
                id=self.rpc_schema.get_block_by_hash[1],
                params=[eth_utils.to_eth_converters[eth_types.Hash32](block_id), full],
            )
        )
        return eth_models.Block.parse_obj(data)

    async def get_block_by_number(
        self, block_id: eth_types.DefaultBlockIdentifier, full: bool
    ) -> Optional[eth_models.Block]:
        """Returns information about a block by block number.

        Calls the eth_getBlockByNumber.

        :param block_id: Integer of a block number, or the string
                          "earliest", "latest" or "pending", as in the
                          default block parameter.
        :param full: If true it returns the full transaction objects, if false
                     only the hashes of the transactions.

        :returns
            Union[eth_models.Block, None]: A block object, or None when no block was
                                         found.
        """
        if block_id not in ["pending", "latest", "earliest"]:
            block_id = eth_utils.to_eth_converters[int](block_id)
        return eth_models.Block.parse_obj(
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.get_block_by_number[0],
                    id=self.rpc_schema.get_block_by_number[1],
                    params=[block_id, full],
                )
            )
        )

    async def submit_hashrate(
        self, hashrate: eth_types.HexStr, identifier: eth_types.HexStr,
    ) -> bool:
        """Return code at a given address during specified block.

        Calls eth_submitHashrate.

        :param hashrate: A hexadecimal string representation of the hash rate.
        :param identifier: A random hexadecimal ID identifying the client.

        :returns
            bool: True if submitting went through and false otherwise.
        """
        return eth_utils.result_truthiness(
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.submit_hashrate[0],
                    id=self.rpc_schema.submit_hashrate[1],
                    params=[hashrate, identifier],
                )
            )
        )

    async def shh_version(self) -> str:
        """Returns the current whisper protocol version.

        Calls shh_version.

        :returns
            str: The current whisper protocol version.
        """
        return await self.rpc(
            eth_models.JSONRPCRequest(
                method=self.rpc_schema.shh_version[0], id=self.rpc_schema.shh_version[1]
            )
        )

    async def shh_post(self, whisper: eth_models.Message) -> bool:
        """Sends a whisper message.

        Calls shh_post.

        :param whisper: The whisper post object.

        :returns
            bool: Returns true if the message was send, otherwise false.
        """
        return await self.rpc(
            eth_models.JSONRPCRequest(
                method=self.rpc_schema.shh_post[0],
                id=self.rpc_schema.shh_post[1],
                params=[whisper.dict()],
            )
        )

    async def shh_new_identity(self) -> eth_types.Data:
        """Creates new whisper identity in the client.

        Calls shh_newIdentity.

        :returns
            eth_types.Data: The address of the new identity (60 Bytes).
        """
        return await self.rpc(
            eth_models.JSONRPCRequest(
                method=self.rpc_schema.shh_new_identity[0],
                id=self.rpc_schema.shh_new_identity[1],
            )
        )

    async def shh_has_identity(self, identifier: eth_types.Data) -> bool:
        """Checks if the client hold the private keys for a given identity.

        Calls shh_hasIdentity.

        :params id: The identity address to check.

        :returns
            bool: Returns true if the message was send, otherwise false.
        """
        return eth_utils.result_truthiness(
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.shh_has_identity[0],
                    id=self.rpc_schema.shh_has_identity[1],
                    params=[identifier],
                )
            )
        )

    async def shh_new_group(self) -> eth_types.Data:
        """Create a new whisper group (?).

        Calls shh_newGroup.

        :returns
            eth_types.Data: The address of the new group (60 Bytes).
        """
        return await self.rpc(
            eth_models.JSONRPCRequest(
                method=self.rpc_schema.shh_new_group[0],
                id=self.rpc_schema.shh_new_group[1],
            )
        )

    async def shh_add_to_group(self, identifier: eth_types.Data) -> bool:
        """Add an identity to a group (?).

        Calls shh_addToGroup.

        :params id: The identity address to add to a group.

        :returns
            bool: Returns true if the identity was successfully added to the
                  group, otherwise false (?).
        """
        return eth_utils.result_truthiness(
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.shh_add_to_group[0],
                    id=self.rpc_schema.shh_add_to_group[1],
                    params=[identifier],
                )
            )
        )

    async def shh_new_filter(self, whisper_filter: eth_models.WhisperFilter) -> int:
        """Creates filter to notify, when client receives whisper message
        matching the filter options.

        Calls shh_newFilter.

        :params filter: The filter options.

        :returns
            int: The newly created filter.
        """
        return eth_utils.conversions.to_int(
            await self.rpc(
                eth_models.JSONRPCRequest(
                    method=self.rpc_schema.shh_new_filter[0],
                    id=self.rpc_schema.shh_new_filter[1],
                    params=[whisper_filter.dict()],
                )
            )
        )

    async def shh_uninstall_filter(self, identifier: int) -> bool:
        """Uninstalls a filter with given id. Should always be called when
        watch is no longer needed. Additionally, filters timeout when they
        are not requested with shh_getFilterChanges for a period of time.

        Calls shh_uninstallFilter.

        :params id: The filter id.

        :returns
            bool: True if the filter was successfully uninstalled,
                  otherwise false.
        """
        return await self.rpc(
            eth_models.JSONRPCRequest(
                method=self.rpc_schema.shh_uninstall_filter[0],
                id=self.rpc_schema.shh_uninstall_filter[1],
                params=[conversions.to_hex(identifier)],
            )
        )

    async def get_shh_filter_changes(self, identifier: int) -> List[eth_models.Message]:
        """Polling method for whisper filters. Returns new messages since the
        last call of this method.

        Note: Calling the shh_getMessages method, will reset the buffer for
        this method, so that you won’t receive duplicate messages.

        Calls shh_getFilterChanges.

        :param identifier: The filter id.

        :returns
            List[eth_models.Messages]: Array of messages received since last poll.
        """
        result = await self.rpc(
            eth_models.JSONRPCRequest(
                method=self.rpc_schema.get_shh_filter_changes[0],
                id=self.rpc_schema.get_shh_filter_changes[1],
                params=[conversions.to_hex(identifier)],
            )
        )

        return eth_models.iterate_list(eth_models.Message, result)

    async def get_shh_messages(
        self, identifier: int
    ) -> Union[List[eth_models.Message], bool]:
        """Get all messages matching a filter. Unlike shh_getFilterChanges
        this returns all messages.

        Calls shh_getMessages.

        :param identifier: The filter id.

        :returns
            List[eth_models.Messages]: Array of messages received.
            bool: False if no messages.
        """
        result = await self.rpc(
            eth_models.JSONRPCRequest(
                method=self.rpc_schema.get_shh_messages[0],
                id=self.rpc_schema.get_shh_messages[1],
                params=[conversions.to_hex(identifier)],
            )
        )

        truthiness = eth_utils.result_truthiness(result)
        if isinstance(truthiness, bool):
            return truthiness

        return eth_models.iterate_list(eth_models.Message, result)
