"""Exceptions for fasteth."""


class JSONRPCError(Exception):
    """An ethereum JSON RPC error."""

    pass


class ParseError(JSONRPCError):
    """Invalid JSON was received by the server.

    An error occurred on the server while parsing the JSON text.
    """

    pass


class InvalidRequest(JSONRPCError):
    """The JSON sent is not a valid Request object."""

    pass


class MethodNotFound(JSONRPCError):
    """The method does not exist/is not available."""

    pass


class InvalidParams(JSONRPCError):
    """Invalid method parameter(s)."""

    pass


class InternalError(JSONRPCError):
    """Internal JSON-RPC error."""

    pass


class ServerError(JSONRPCError):
    """Reserved for implementation-defined server-errors."""


class EthereumRPCError(JSONRPCError):
    """A generic ethereum RPC error."""

    pass


class UnauthorizedError(EthereumRPCError):
    """Action is not authorized."""

    pass


class ActionNotAllowed(EthereumRPCError):
    """Should be used when some action is not allowed, e.g. preventing
    an action, while another depending action is processing on, like
    sending again when a confirmation popup is shown to the user
    """

    pass


class ExecutionError(EthereumRPCError):
    """Will contain a subset of custom errors in the data field. """

    pass


class NotFound(ExecutionError):
    """Something which should be in response is not found."""

    pass


class RequiresEther(ExecutionError):
    """Action requires a value of ether."""

    pass


class GasTooLow(ExecutionError):
    """The gas value provided is too low."""

    pass


class GasLimitExceeded(ExecutionError):
    """The gas limit has been exceeded."""

    pass


class Rejected(ExecutionError):
    """Action rejected because of contents."""

    pass


class EtherTooLow(ExecutionError):
    """The provided ether value was too low."""

    pass
