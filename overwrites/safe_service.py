import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple, Union

from web3 import Web3

from gnosis.eth import EthereumClient
from gnosis.eth.constants import GAS_CALL_DATA_BYTE, NULL_ADDRESS, SENTINEL_ADDRESS
from gnosis.eth.contracts import get_cpk_factory_contract, get_proxy_factory_contract
from gnosis.safe import Safe
from gnosis.safe.exceptions import CannotRetrieveSafeInfoException
from gnosis.safe.safe import SafeInfo
from web3.types import BlockIdentifier, Wei

from ..exceptions import NodeConnectionException
from ..models import InternalTx

logger = logging.getLogger(__name__)



class SafeCustom(Safe):
    def retrieve_all_info(
        self, block_identifier: Optional[BlockIdentifier] = "latest"
    ) -> SafeInfo:
        """
        Get all Safe info in the same batch call.
        :param block_identifier:
        :return:
        :raises: CannotRetrieveSafeInfoException
        """
        try:
            contract = self.get_contract()
            master_copy = self.retrieve_master_copy_address()
            fallback_handler = self.retrieve_fallback_handler()
            guard = self.retrieve_guard()

            results = self.ethereum_client.batch_call(
                [
                    contract.functions.getModulesPaginated(
                        SENTINEL_ADDRESS, 20
                    ),  # Does not exist in version < 1.1.1
                    contract.functions.nonce(),
                    contract.functions.getOwners(),
                    contract.functions.getThreshold(),
                    contract.functions.VERSION(),
                ],
                # Nethermind RPC Call Fix
                from_address=NULL_ADDRESS,
                block_identifier=block_identifier,
                raise_exception=False,
            )
            modules_response, nonce, owners, threshold, version = results
            if modules_response:
                modules, next_module = modules_response
            if (
                not modules_response or next_module != SENTINEL_ADDRESS
            ):  # < 1.1.1 or still more elements in the list
                modules = self.retrieve_modules()
            return SafeInfo(
                self.address,
                fallback_handler,
                guard,
                master_copy,
                modules,
                nonce,
                owners,
                threshold,
                version,
            )
        except (ValueError, BadFunctionCallOutput) as e:
            raise CannotRetrieveSafeInfoException(self.address) from e

class SafeServiceException(Exception):
    pass


class CannotGetSafeInfo(SafeServiceException):
    pass


EthereumAddress = str


@dataclass
class SafeCreationInfo:
    created: datetime
    creator: EthereumAddress
    factory_address: EthereumAddress
    master_copy: Optional[EthereumAddress]
    setup_data: Optional[bytes]
    transaction_hash: str


class SafeServiceProvider:
    def __new__(cls):
        if not hasattr(cls, "instance"):
            from django.conf import settings

            tracing_enabled = bool(settings.ETHEREUM_TRACING_NODE_URL)
            node_url = (
                settings.ETHEREUM_TRACING_NODE_URL
                if tracing_enabled
                else settings.ETHEREUM_NODE_URL
            )
            cls.instance = SafeService(EthereumClient(node_url), tracing_enabled)
        return cls.instance

    @classmethod
    def del_singleton(cls):
        if hasattr(cls, "instance"):
            del cls.instance


class SafeService:
    def __init__(self, ethereum_client: EthereumClient, tracing_enabled: bool):
        self.ethereum_client = ethereum_client
        self.tracing_enabled = tracing_enabled
        dummy_w3 = Web3()  # Not needed, just used to decode contracts
        self.proxy_factory_contract = get_proxy_factory_contract(dummy_w3)
        self.cpk_proxy_factory_contract = get_cpk_factory_contract(dummy_w3)

    def get_safe_creation_info(self, safe_address: str) -> Optional[SafeCreationInfo]:
        try:
            creation_internal_tx = (
                InternalTx.objects.filter(
                    ethereum_tx__status=1  # Ignore Internal Transactions for failed Transactions
                )
                .select_related("ethereum_tx__block")
                .get(contract_address=safe_address)
            )
            creation_ethereum_tx = creation_internal_tx.ethereum_tx

            created_time = creation_ethereum_tx.block.timestamp

            parent_internal_tx = self._get_parent_internal_tx(creation_internal_tx)

            creator = (parent_internal_tx or creation_ethereum_tx)._from
            proxy_factory = creation_internal_tx._from

            master_copy: Optional[str] = None
            setup_data: Optional[bytes] = None
            data = (
                bytes(parent_internal_tx.data)
                if parent_internal_tx
                else bytes(creation_ethereum_tx.data)
            )
            result = self._decode_proxy_factory(data) or self._decode_cpk_proxy_factory(
                data
            )
            if result:
                master_copy, setup_data = result
            if not (master_copy and setup_data):
                if setup_internal_tx := self._get_next_internal_tx(
                    creation_internal_tx
                ):
                    master_copy = setup_internal_tx.to
                    setup_data = setup_internal_tx.data
        except InternalTx.DoesNotExist:
            return None
        except IOError as exc:
            raise NodeConnectionException from exc

        return SafeCreationInfo(
            created_time,
            creator,
            proxy_factory,
            master_copy,
            setup_data,
            creation_internal_tx.ethereum_tx_id,
        )

    def get_safe_info(self, safe_address: str) -> SafeInfo:
        try:
            safe = SafeCustom(safe_address, self.ethereum_client)
            return safe.retrieve_all_info()
        except IOError as exc:
            raise NodeConnectionException from exc
        except CannotRetrieveSafeInfoException as e:
            raise CannotGetSafeInfo from e

    def _decode_proxy_factory(
        self, data: Union[bytes, str]
    ) -> Optional[Tuple[str, bytes]]:
        try:
            _, data_decoded = self.proxy_factory_contract.decode_function_input(data)
            master_copy = (
                data_decoded.get("masterCopy")
                or data_decoded.get("_mastercopy")
                or data_decoded.get("_singleton")
                or data_decoded.get("singleton")
            )
            setup_data = data_decoded.get("data") or data_decoded.get("initializer")
            if master_copy and setup_data is not None:
                return master_copy, setup_data

            logger.error(
                "Problem decoding proxy factory, data_decoded=%s", data_decoded
            )
            return None
        except ValueError:
            return None

    def _decode_cpk_proxy_factory(
        self, data: Union[bytes, str]
    ) -> Optional[Tuple[str, bytes]]:
        try:
            _, data_decoded = self.cpk_proxy_factory_contract.decode_function_input(
                data
            )
            master_copy = data_decoded.get("masterCopy")
            setup_data = data_decoded.get("data")
            return master_copy, setup_data
        except ValueError:
            return None

    def _get_next_internal_tx(self, internal_tx: InternalTx) -> Optional[InternalTx]:
        if child_trace := internal_tx.get_child(0):
            return child_trace
        if not self.tracing_enabled:
            return None
        try:
            next_traces = self.ethereum_client.parity.get_next_traces(
                internal_tx.ethereum_tx_id,
                internal_tx.trace_address_as_list,
                remove_calls=True,
            )
            return next_traces and InternalTx.objects.build_from_trace(
                next_traces[0], internal_tx.ethereum_tx
            )
        except ValueError:
            return None

    def _get_parent_internal_tx(self, internal_tx: InternalTx) -> InternalTx:
        if parent_trace := internal_tx.get_parent():
            return parent_trace
        if not self.tracing_enabled:
            return None
        try:
            previous_trace = self.ethereum_client.parity.get_previous_trace(
                internal_tx.ethereum_tx_id,
                internal_tx.trace_address_as_list,
                skip_delegate_calls=True,
            )
            return previous_trace and InternalTx.objects.build_from_trace(
                previous_trace, internal_tx.ethereum_tx
            )
        except ValueError:
            return None
