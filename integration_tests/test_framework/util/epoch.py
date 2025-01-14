from dataclasses import dataclass
import sys


@dataclass
class EpochErrorInfo:
    """
    A dataclass to encapsulate information about epoch-related errors.
    epoch (any): The epoch value that caused the error.
    error_code (int): The error code.
    error_msg (callable): A function that takes the type and args as arguments and returns the error message.
    """

    epoch: any
    error_code: int
    error_msg: str


epoch_invalid_epoch_type_error = EpochErrorInfo(
    epoch=1,
    error_code=-32602,
    error_msg="Invalid params: invalid type: integer `1`, expected an epoch number or 'latest_mined', 'latest_state', 'latest_checkpoint', 'latest_finalized', 'latest_confirmed' or 'earliest'.",
)


epoch_epoch_number_too_large_error = EpochErrorInfo(
    epoch=hex(sys.maxsize),
    error_code=-32602,
    error_msg="Invalid params: expected a numbers with less than largest epoch number.",
)

epoch_empty_epoch_string_error = EpochErrorInfo(
    epoch="0x",
    error_code=-32602,
    error_msg="Invalid params: Invalid epoch number: cannot parse integer from empty string.",
)

epoch_invalid_digit_epoch_error = EpochErrorInfo(
    epoch="0xZZZ",
    error_code=-32602,
    error_msg="Invalid params: Invalid epoch number: invalid digit found in string.",
)

epoch_missing_hex_prefix_error = EpochErrorInfo(
    epoch="-1",
    error_code=-32602,
    error_msg="Invalid params: Invalid epoch number: missing 0x prefix.",
)
