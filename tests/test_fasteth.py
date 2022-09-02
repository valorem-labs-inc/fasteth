import asyncio
import re
from typing import AsyncGenerator, Dict, List, Optional, Type, Union

import pytest
from eth_utils import (
    encode_hex,
    to_bytes,
    to_checksum_address,
    to_hex,
    to_int,
    to_normalized_address,
    to_text,
)
from pydantic import BaseModel

import fasteth
from fasteth import exceptions
from fasteth import models as eth_models
from fasteth import types as eth_types
from fasteth import utils as eth_utils

# TODO(add more rigorous testing and parametrized testing)
# These are all "golden path" tests, if you will.

test_address = eth_types.HexAddress(
    eth_types.HexStr("0x36273803306a3C22bc848f8Db761e974697ece0d")
)
test_any_address = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
storage_address = eth_types.HexAddress(
    eth_types.HexStr("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB")
)
test_data = eth_types.HexStr("0x00")
zero_block = eth_types.HexAddress(eth_types.HexStr(test_data))
zero_block_hash: eth_types.Hash32 = eth_utils.to_py_converters[eth_types.Hash32](
    zero_block
)
whisper_client = "2"
# Full: Geth\/v[0-9]+\.[0-9]+\.[0-9]+\-[A-z]+\-[0-9A-f]+\/[A-z-0-9]+\/[A-z-0-9.]+
infura_client = r"Geth\/v[0-9]+\.[0-9]+\.[0-9]+.+"
ganache_client = r"EthereumJS\sTestRPC\/v[0-9]+\.[0-9]+\.[0-9]+\/ethereum\-js"
test_block_hash = "0xba6c9192229ef4fc8615b510abd2c602f3805b1e51ff8892fb0964e1988ba1e2"
test_hashrate_rate = eth_types.HexStr(
    "0x0000000000000000000000000000000000000000000000000000000000500000"
)
test_hashrate_id = eth_types.HexStr(
    "0x59daa26581d0acd1fce254fb7e85952f4c09d0915afd33d3886cd914bc7d283c"
)
test_hexstring = "0x74657374"  # "test"
test_block_num = "0x7c5b7a"
test_block_id = "0xB6D1B0"
test_data_list = ["0x74657374", "0x74657374"]
test_topic_list = ["test", "test"]
latest = "latest"
test_whisper_filter = eth_models.WhisperFilter(
    to=eth_utils.to_eth_converters[eth_types.HexAddress](test_address),
    topics=test_topic_list,
)
test_whisper_filter_id = 7
test_whisper_id = 0
test_whisper_address: eth_types.Data = eth_utils.to_py_converters[eth_types.Data](
    test_data
)


class PyableTestBench(eth_models.Ethable, BaseModel):
    """Benchmark dataclass for the pyable utility function."""

    hash32: eth_types.Hash32
    address: eth_types.Address
    checksumaddress: eth_types.ChecksumAddress
    hexaddress: eth_types.HexAddress
    hexstring: eth_types.HexStr
    data: eth_types.Data
    blocknumber: eth_types.BlockNumber
    integer: int
    # Cannot be set through dacite
    data_list: Optional[list[eth_types.Data]] = None
    anyaddress: Optional[eth_types.Address] = None
    blockid: Optional[eth_types.BlockIdentifier] = None

    def dict(self: Type[eth_models.T]) -> Dict:
        """Benchmark without AutoEthable."""
        return {
            "hash32": encode_hex(self.hash32),
            "address": encode_hex(self.address),
            "checksumaddress": to_checksum_address(self.checksumaddress),
            "hexaddress": to_normalized_address(self.hexaddress),
            "anyaddress": to_normalized_address(self.anyaddress),
            "hexstring": to_hex(None, None, self.hexstring),
            "data": to_hex(None, None, self.data),
            "data_list": list(map(lambda z: to_hex(None, None, z), self.data_list)),
            "blocknumber": to_hex(self.blocknumber),
            "integer": to_hex(self.integer),
            "blockid": to_hex(self.blockid),
        }

    @classmethod
    def parse_obj(cls: Type[eth_models.T], data: Dict):
        data["hash32"] = to_bytes(hexstr=data["hash32"])
        data["address"] = to_bytes(None, data["address"])
        data["hexaddress"] = to_normalized_address(data["hexaddress"])
        data["checksumaddress"] = data["checksumaddress"]
        data["anyaddress"] = to_bytes(None, data["anyaddress"])
        data["hexstring"] = to_text(None, data["hexstring"])
        data["data"] = to_text(None, data["data"])
        data["data_list"] = list(map(lambda z: to_text(z), data["data_list"]))
        data["blocknumber"] = to_int(None, data["blocknumber"])
        data["integer"] = to_int(None, data["integer"])
        data["blockid"] = to_int(None, data["blockid"])
        return cls(**data)


class PyableTest(eth_models.AutoEthable):
    """Test dataclass for the pyable utility function."""

    hash32: eth_types.Hash32
    address: eth_types.Address
    checksumaddress: eth_types.ChecksumAddress
    hexaddress: eth_types.HexAddress
    anyaddress: eth_types.Address
    hexstring: eth_types.HexStr
    data: eth_types.Data
    data_list: List[eth_types.Data]
    blocknumber: eth_types.BlockNumber
    blockid: eth_types.BlockIdentifier
    integer: int


def test_version():
    assert fasteth.__version__ == "0.1.0"


# TODO(Add a benchmark here for an explicitly defined conversion to and from)
# both of these are using the type system to perform a conversion.
class BenchConversionData:
    def __init__(self):
        self.result = {
            "hash32": test_block_hash.lower(),
            "address": test_address.lower(),
            "hexaddress": test_address.lower(),
            "checksumaddress": test_address,
            "hexstring": test_hexstring.lower(),
            "data": test_hexstring.lower(),
            "blocknumber": hex(56333),
            "integer": hex(9000),
            "data_list": test_data_list,
            "anyaddress": test_any_address.lower(),
            "blockid": test_block_num,
        }
        self.result_expect = {
            "hash32": to_bytes(None, self.result["hash32"]),
            "address": to_bytes(None, self.result["address"]),
            "hexaddress": to_normalized_address(self.result["hexaddress"]),
            "checksumaddress": to_checksum_address(self.result["checksumaddress"]),
            "anyaddress": to_bytes(None, self.result["anyaddress"]),
            "hexstring": to_text(None, self.result["hexstring"]),
            "data": to_text(None, self.result["data"]),
            "data_list": list(map(lambda z: to_text(z), self.result["data_list"])),
            "blocknumber": to_int(None, self.result["blocknumber"]),
            "integer": to_int(None, self.result["integer"]),
            "blockid": to_int(None, self.result["blockid"]),
        }


@pytest.fixture(scope="module")
def bench_data():
    return BenchConversionData()


def assert_keys_equal(obj: Union[PyableTest, PyableTestBench], exp: Dict):
    # Test Pyable coversions properly converted.
    assert obj.hash32 == exp["hash32"]
    assert obj.address == exp["address"]
    assert obj.hexstring == exp["hexstring"]
    assert obj.hexaddress == exp["hexaddress"]
    assert obj.anyaddress == exp["anyaddress"]
    assert obj.checksumaddress == exp["checksumaddress"]
    assert obj.data == exp["data"]
    assert obj.data_list == exp["data_list"]
    assert obj.blocknumber == exp["blocknumber"]
    assert obj.integer == exp["integer"]
    assert obj.blockid == exp["blockid"]


def assert_dict_equal(test: Dict, exp: Dict):
    # Test Pyable coversions properly converted.
    assert test["hash32"] == exp["hash32"]
    assert test["address"] == exp["address"]
    assert test["hexstring"] == exp["hexstring"]
    assert test["hexaddress"] == exp["hexaddress"]
    assert test["anyaddress"] == exp["anyaddress"]
    assert test["checksumaddress"] == exp["checksumaddress"]
    assert test["data"] == exp["data"]
    assert test["data_list"] == exp["data_list"]
    assert test["blocknumber"] == exp["blocknumber"]
    assert test["integer"] == exp["integer"]
    assert test["blockid"] == exp["blockid"]


def test_ethable_pyable(benchmark, bench_data):

    pyable_test = PyableTest.parse_obj(bench_data.result.copy())

    # Test Pyable coversions properly converted.
    assert_keys_equal(pyable_test, bench_data.result_expect)

    # Leaving this here as reference on how to do a benchmark.
    # The whole function should be decorated with:  @pytest.mark.benchmark
    # @benchmark
    # def convert_result() -> dict:
    #     """Benchmark of the pyable utility function."""
    #     pyable_t = PyableTest.parse_obj(bench_data.result.copy())
    #     return pyable_t.dict()

    rebuilt = pyable_test.dict()
    # Assert roundtrip.
    assert_dict_equal(bench_data.result, rebuilt)


def test_explicit(benchmark, bench_data):

    pyable_test = PyableTestBench.parse_obj(bench_data.result.copy())

    # Test Pyable coversions properly converted.
    assert_keys_equal(pyable_test, bench_data.result_expect)

    rebuilt = pyable_test.dict()

    # Assert roundtrip.
    assert_dict_equal(bench_data.result, rebuilt)


def test_transaction_dataclass():
    transaction_data = {
        "from_address": storage_address.lower(),
        "to": test_address.lower(),
        "data": test_data,
        "gasPrice": hex(20000),
    }

    transaction = eth_models.Transaction.parse_obj(transaction_data.copy())
    eth_payload: dict = transaction.dict()

    assert "from" in eth_payload
    assert "to" in eth_payload
    assert "gasPrice" in eth_payload
    assert eth_payload["from"] == transaction_data["from_address"]
    assert eth_payload["to"] == transaction_data["to"]
    assert eth_payload["gasPrice"] == transaction_data["gasPrice"]


@pytest.fixture(scope="module")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="module")
async def async_rpc() -> AsyncGenerator:
    """Returns an AsyncEthereumJSONRPC instance."""
    # This fixture is reused for the entire module test run.
    # Temporary Infura ID
    # TODO(delete this infura project later)
    jsonrpc = fasteth.AsyncEthereumJSONRPC()
    yield jsonrpc


@pytest.mark.asyncio
async def test_client_version(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the client version."""
    client_version = await async_rpc.client_version()
    assert isinstance(client_version, str)
    assert re.match(infura_client, client_version) or re.match(
        ganache_client, client_version
    )


@pytest.mark.asyncio
async def test_sha3(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting a sha3/Keccak-256 hash."""
    data_to_hash = "0x68656c6c6f20776f726c64"
    hashed = "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
    hashed_ret = await async_rpc.sha3(
        eth_utils.to_py_converters[eth_types.Data](data_to_hash)
    )
    assert hashed == eth_utils.to_eth_converters[eth_types.Hash32](hashed_ret)


@pytest.mark.asyncio
async def test_network_version(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the network version."""
    network_version = await async_rpc.network_version()
    assert (
        network_version == eth_models.Network.Rinkeby
        or network_version == eth_models.Network.Ganache
    )


@pytest.mark.asyncio
async def test_network_listening(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the network version."""
    network_listening = await async_rpc.network_listening()
    assert network_listening


@pytest.mark.asyncio
async def test_network_peer_count(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the network version."""
    peer_count = await async_rpc.network_peer_count()
    assert isinstance(peer_count, int)


@pytest.mark.asyncio
async def test_protocol_version(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the network version."""
    protocol_version = await async_rpc.protocol_version()
    assert protocol_version >= 65


@pytest.mark.asyncio
async def test_syncing(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the network sync status."""
    # Our test client should not by in a syncing state.
    sync_status = await async_rpc.syncing()
    assert not sync_status.syncing


@pytest.mark.asyncio
async def test_coinbase(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the coinbase address for the eth client"""
    # We expect this to fail, as our test client does not have a coinbase address.
    try:
        await async_rpc.coinbase()
    except exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_mining(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test checking if eth client is mining"""
    # We our test client to not be mining.
    result = await async_rpc.mining()
    # We really only care about the result.
    assert isinstance(result, bool)


@pytest.mark.asyncio
async def test_hashrate(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting client hashrate."""
    assert (await async_rpc.hashrate()) == 0


@pytest.mark.asyncio
async def test_gas_price(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the gas price in wei."""
    gas_price = await async_rpc.gas_price()
    assert isinstance(gas_price, int)


@pytest.mark.asyncio
async def test_accounts(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the accounts owned by client."""
    accounts = await async_rpc.accounts()
    assert isinstance(accounts, list)


@pytest.mark.asyncio
async def test_block_number(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the network version."""
    block_number = await async_rpc.block_number()
    # TODO(figure out with fasteth.eth_typing.BlockNumber fails here)
    assert isinstance(block_number, int)


@pytest.mark.asyncio
async def test_get_balance(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting balance of an account."""
    balance = await async_rpc.get_balance(address=test_address)
    assert isinstance(balance, int)


@pytest.mark.asyncio
async def test_get_storage_at(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting storage for an address at a given position."""
    # data = await async_rpc.get_storage_at(storage_address, test_data, latest)
    # TODO(Find a better test address and position.)
    # assert data == test_data
    pass


@pytest.mark.asyncio
async def test_get_transaction_count(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting transaction count for a given address."""
    assert isinstance((await async_rpc.get_transaction_count(test_address)), int)


@pytest.mark.asyncio
async def test_get_block_transaction_count_by_hash(
    async_rpc: fasteth.AsyncEthereumJSONRPC,
):
    """Test getting the block transaction count by hash."""
    assert isinstance(
        (await async_rpc.get_block_transaction_count_by_hash(zero_block_hash)), int,
    )


@pytest.mark.asyncio
async def test_get_block_transaction_count_by_number(
    async_rpc: fasteth.AsyncEthereumJSONRPC,
):
    """Test getting the block transaction count by number."""
    assert isinstance(
        (
            await async_rpc.get_block_transaction_count_by_number(
                block_identifier=eth_types.BlockNumber(0)
            )
        ),
        int,
    )


@pytest.mark.asyncio
async def test_get_uncle_count_by_block_hash(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the uncle block count by hash."""
    assert isinstance(
        (await async_rpc.get_uncle_count_by_block_hash(zero_block_hash)), int,
    )


@pytest.mark.asyncio
async def test_get_uncle_count_by_block_number(
    async_rpc: fasteth.AsyncEthereumJSONRPC,
):
    """Test getting the block uncle count by number."""
    assert isinstance(
        (
            await async_rpc.get_uncle_count_by_block_number(
                block_identifier=test_block_num
            )
        ),
        int,
    )


@pytest.mark.asyncio
async def test_get_code(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting code from a given address at a given block."""
    storage_contents = await async_rpc.get_code(storage_address)
    assert type(storage_contents) == str


@pytest.mark.asyncio
async def test_sign(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test signing and returning the signature."""
    # We expect this to fail because it is unsupported on our test endpoint.
    try:
        await async_rpc.sign(address=test_address, message=test_data)
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_sign_transaction(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test signing a transaction and returning the signed transaction."""
    transaction = eth_models.Transaction(from_address=storage_address, data=test_data)
    # We expect this to fail because it is unsupported on our test endpoint.
    try:
        await async_rpc.sign_transaction(transaction=transaction)
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_send_transaction(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test signing a transaction and returning the signed transaction."""
    transaction = eth_models.Transaction(from_address=storage_address, data=test_data)
    # We expect this to fail because it is unsupported on our test endpoint.
    try:
        await async_rpc.send_transaction(transaction=transaction)
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_send_raw_transaction(async_rpc: fasteth.AsyncEthereumJSONRPC):
    # TODO(Fix this test to use a real tx data that works on Rinkeby)
    try:
        await async_rpc.send_raw_transaction(
            eth_types.HexStr(
                "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8e"
                "b970870f072445675"
            )
        )
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_call(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test call to a contract function without posting a transaction."""
    transaction = eth_models.Transaction(from_address=storage_address, data=test_data)
    # TODO(Get working test data in place)
    try:
        await async_rpc.call(transaction=transaction, block_identifier=latest)
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_estimate_gas(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test call to a contract function without posting a transaction."""
    transaction = eth_models.Transaction(from_address=storage_address, data=test_data)
    # TODO(Get working test data in place)
    try:
        await async_rpc.estimate_gas(
            transaction=transaction, block_identifier="pending"
        )
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_get_block_by_hash(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting a block by number."""
    block = await async_rpc.get_block_by_hash(zero_block_hash, True)
    assert isinstance(block, eth_models.Block)


@pytest.mark.asyncio
async def test_get_block_by_number(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting a block by number."""
    block = await async_rpc.get_block_by_number(eth_types.BlockNumber(0), True)
    assert isinstance(block, eth_models.Block)


@pytest.mark.asyncio
async def test_submit_hashrate(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test submitting a hashrate."""
    submitted = await async_rpc.submit_hashrate(test_hashrate_rate, test_hashrate_id)
    assert isinstance(submitted, bool)
    print(submitted)


@pytest.mark.asyncio
async def test_shh_version(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the client version."""
    try:
        client_version = await async_rpc.shh_version()
        assert isinstance(client_version, str)
        assert client_version == whisper_client
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_shh_post(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test sending a whisper message."""
    try:
        whisper = eth_models.Message(
            from_address=storage_address,
            to=test_address,
            topics=test_topic_list,
            payload=test_data,
            priority=100,
            ttl=100,
        )
        success = await async_rpc.shh_post(whisper)
        assert isinstance(success, bool)
        assert success is True
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_shh_new_identity(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test creating a new whisper identity in the client."""
    try:
        identity = await async_rpc.shh_new_identity()
        assert isinstance(identity, str)
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_shh_has_identity(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test if the client holds the private keys for a given identity."""
    try:
        identity = await async_rpc.shh_has_identity(test_whisper_address)
        assert isinstance(identity, bool)
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_shh_new_group(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test creating a new whisper group."""
    try:
        identity = await async_rpc.shh_new_group()
        assert isinstance(identity, str)
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_shh_add_to_group(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test if an identity was added to a group."""
    try:
        identity = await async_rpc.shh_add_to_group(test_whisper_address)
        assert isinstance(identity, bool)
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_shh_new_filter(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test creating a new filter."""
    try:
        identity = await async_rpc.shh_new_filter(test_whisper_filter)
        assert isinstance(identity, int)
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_shh_uninstall_filter(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test uninstalling a filter."""
    try:
        # We need a filter installed
        identity = await async_rpc.shh_new_filter(test_whisper_filter)
        success = await async_rpc.shh_uninstall_filter(identity)
        assert isinstance(success, bool)
        assert success is True
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_get_shh_filter_changes(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test polling method for whisper messages."""
    try:
        await async_rpc.get_shh_filter_changes(test_whisper_filter_id)
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_get_shh_messages(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting all messages matching a filter."""
    try:
        await async_rpc.get_shh_messages(test_whisper_filter_id)
    except fasteth.exceptions.JSONRPCError:
        pass


if __name__ == "__main__":
    """For running directly via CLI."""
    import sys

    import pytest

    pytest.main(sys.argv)
