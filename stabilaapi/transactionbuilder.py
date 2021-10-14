# --------------------------------------------------------------------
# Copyright (c) iEXBase. All rights reserved.
# Licensed under the MIT License.
# See License.txt in the project root for license information.
# --------------------------------------------------------------------

from datetime import datetime
from typing import (
    Any,
    Tuple,
    List
)

from eth_abi import encode_abi
from stb_utils import (
    is_string,
    is_integer,
    is_boolean,
    is_hex,
    encode_hex
)

from stabilaapi.exceptions import (
    InvalidStabilaError,
    StabilaError,
    InvalidAddress
)
from stabilaapi.common.validation import is_valid_url

DEFAULT_TIME = datetime.now()
START_DATE = int(DEFAULT_TIME.timestamp() * 1000)


class TransactionBuilder(object):
    def __init__(self, stabila):
        self.stabila = stabila

    def send_transaction(self, to, amount, account=None):
        """Creates a transaction of transfer.
        If the recipient address does not exist, a corresponding account will be created.

        Args:
            to (str): to address
            amount (float): amount
            account (str): from address

        Returns:
            Transaction contract data

        """

        # If the address of the sender is not specified, we prescribe the default
        if account is None:
            account = self.stabila.default_address.hex

        if not self.stabila.isAddress(to):
            raise InvalidStabilaError('Invalid recipient address provided')

        if not isinstance(amount, float) or amount <= 0:
            raise InvalidStabilaError('Invalid amount provided')

        _to = self.stabila.address.to_hex(to)
        _from = self.stabila.address.to_hex(account)

        if _to == _from:
            raise StabilaError('Cannot transfer STB to the same account')

        response = self.stabila.manager.request('/wallet/createtransaction', {
            'to_address': _to,
            'owner_address': _from,
            'amount': self.stabila.toUnit(amount)
        })

        return response

    def send_token(self, to, amount, token_id, account=None):
        """Transfer Token

        Args:
            to (str): is the recipient address
            amount (int): is the amount of token to transfer. must be integer instead of float
            token_id (any): Token Name and id
            account: (str): is the address of the withdrawal account

        Returns:
            Token transfer Transaction raw data

        """

        # If the address of the sender is not specified, we prescribe the default
        if account is None:
            account = self.stabila.default_address.hex

        if not self.stabila.isAddress(to):
            raise InvalidStabilaError('Invalid recipient address provided')

        if not isinstance(amount, int) or amount <= 0:
            raise InvalidStabilaError('Invalid amount provided')

        if not token_id:
            raise InvalidStabilaError('Invalid token ID provided')

        if not self.stabila.isAddress(account):
            raise InvalidStabilaError('Invalid origin address provided')

        _to = self.stabila.address.to_hex(to)
        _from = self.stabila.address.to_hex(account)
        _token_id = self.stabila.toHex(text=str(token_id))

        if _to == _from:
            raise StabilaError('Cannot transfer STB to the same account')

        # In case if "STB" is specified, we redirect to another method.
        if is_string(token_id) and token_id.upper() == 'STB':
            return self.send_transaction(_to, amount, _from)

        return self.stabila.manager.request('/wallet/transferasset', {
            'to_address': _to,
            'owner_address': _from,
            'asset_name': _token_id,
            'amount': amount
        })

    def cd_balance(self, amount, duration, resource, account=None):
        """
        Cds an amount of STB.
        Will give bandwidth OR Ucr and STABILA Power(voting rights)
        to the owner of the cded tokens.

        Args:
            amount (int): number of cded stb
            duration (int): duration in days to be cded
            resource (str): type of resource, must be either "UCR" or "BANDWIDTH"
            account (str): address that is freezing stb account

        """

        # If the address of the sender is not specified, we prescribe the default
        if account is None:
            account = self.stabila.default_address.hex

        if resource not in ('BANDWIDTH', 'UCR',):
            raise InvalidStabilaError('Invalid resource provided: Expected "BANDWIDTH" or "UCR"')

        if not is_integer(amount) or amount <= 0:
            raise InvalidStabilaError('Invalid amount provided')

        if not is_integer(duration) or duration < 3:
            raise InvalidStabilaError('Invalid duration provided, minimum of 3 days')

        if not self.stabila.isAddress(account):
            raise InvalidStabilaError('Invalid address provided')

        response = self.stabila.manager.request('/wallet/cdbalance', {
            'owner_address': self.stabila.address.to_hex(account),
            'cded_balance': self.stabila.toUnit(amount),
            'cded_duration': int(duration),
            'resource': resource
        })

        if 'Error' in response:
            raise StabilaError(response['Error'])

        return response

    def uncd_balance(self, resource='BANDWIDTH', account=None):
        """
        Uncd STB that has passed the minimum cd duration.
        Unfreezing will remove bandwidth and STABILA Power.

        Args:
            resource (str): type of resource, must be either "UCR" or "BANDWIDTH"
            account (str): address that is freezing stb account

        """

        # If the address of the sender is not specified, we prescribe the default
        if account is None:
            account = self.stabila.default_address.hex

        if resource not in ('BANDWIDTH', 'UCR',):
            raise InvalidStabilaError('Invalid resource provided: Expected "BANDWIDTH" or "UCR"')

        if not self.stabila.isAddress(account):
            raise InvalidStabilaError('Invalid address provided')

        response = self.stabila.manager.request('/wallet/uncdbalance', {
            'owner_address': self.stabila.address.to_hex(account),
            'resource': resource
        })

        if 'Error' in response:
            raise ValueError(response['Error'])

        return response

    def purchase_token(self, to: str, token_id: str, amount: int, buyer=None):
        """Purchase a Token
        Creates an unsigned ICO token purchase transaction.

        Args:
            to (str): is the address of the Token issuer
            token_id (str): is the name of the token
            amount (int): is the number of tokens created
            buyer (str): is the address of the Token owner

        """

        if buyer is None:
            buyer = self.stabila.default_address.hex

        if not self.stabila.isAddress(to):
            raise InvalidAddress('Invalid to address provided')

        if not len(token_id):
            raise ValueError('Invalid token ID provided')

        if amount <= 0:
            raise ValueError('Invalid amount provided')

        _to = self.stabila.address.to_hex(to)
        _from = self.stabila.address.to_hex(buyer)

        return self.stabila.manager.request('/wallet/participateassetissue', {
            'to_address': _to,
            'owner_address': _from,
            'asset_name': self.stabila.toHex(text=token_id),
            'amount': int(amount)
        })

    def withdraw_block_rewards(self, address: str = None):
        """Withdraw block rewards
        Creates an unsigned Super Representative award balance withdraw transaction.

        Args:
            address (str): Optional address to withdraw from.

        """
        if not address:
            address = self.stabila.default_address.hex

        if not self.stabila.isAddress(address):
            raise InvalidAddress('Invalid address provided')

        return self.stabila.manager.request('/wallet/withdrawbalance', {
            'owner_address': self.stabila.address.to_hex(address)
        })

    def apply_for_sr(self, url, address=None):
        """Apply to become a super representative

        Args:
            url (str): official website address
            address (str): address

        """

        # If the address of the sender is not specified, we prescribe the default
        if address is None:
            address = self.stabila.default_address.hex

        if not self.stabila.isAddress(address):
            raise StabilaError('Invalid address provided')

        if not is_valid_url(url):
            raise StabilaError('Invalid url provided')

        return self.stabila.manager.request('/wallet/createwitness', {
            'owner_address': self.stabila.address.to_hex(address),
            'url': self.stabila.toHex(text=url)
        })

    def vote(self, votes: List[Tuple[str, int]], voter_address: str = None):
        """Vote
        Vote on the super representative

        Args:
            votes (dict): dictionary of SR address : vote count key-value pair
            voter_address: voter address

        Examples:
            >>> from stabilaapi import Stabila
            >>> data = [
            >>>     ('TRJpw2uqohP7FUmAEJgt57wakRn6aGQU6Z', 1)
            >>> ]
            >>> stabila = Stabila()
            >>> stabila.transaction.vote(data)

        """
        if voter_address is None:
            voter_address = self.stabila.default_address.hex

        _view_vote = []

        # We create a cycle to check all the received data for voting.
        for sr_address, vote_count in votes:
            if not self.stabila.isAddress(sr_address):
                raise InvalidAddress(
                    'Invalid SR address provided: ' + sr_address
                )

            if not is_integer(vote_count) or vote_count <= 0:
                raise ValueError(
                    'Invalid vote count provided for SR: ' + sr_address
                )

            _view_vote.append({
                'vote_address': self.stabila.address.to_hex(sr_address),
                'vote_count': int(vote_count)
            })

        return self.stabila.manager.request('/wallet/votewitnessaccount', {
            'owner_address': self.stabila.address.to_hex(voter_address),
            'votes': _view_vote
        })

    def create_proposal(self, parameters: Any, issuer_address=None):
        """Creates a proposal to modify the network.
        Can only be created by a current Super Representative.

        Args:
            parameters (Any): proposal parameters
            issuer_address: owner address

        Examples:
            >>> from stabilaapi import Stabila
            >>> data = [
            >>>     {'key': 1, 'value': 2},
            >>>     {'key': 1, 'value': 2}
            >>> ]
            >>> stabila = Stabila()
            >>> stabila.transaction.create_proposal(data)


        """
        if issuer_address is None:
            issuer_address = self.stabila.default_address.hex

        if not self.stabila.isAddress(issuer_address):
            raise InvalidAddress('Invalid issuerAddress provided')

        return self.stabila.manager.request('/wallet/proposalcreate', {
            'owner_address': self.stabila.address.to_hex(issuer_address),
            'parameters': parameters
        })

    def vote_proposal(self, proposal_id, has_approval, voter_address=None):
        """Proposal approval

        Args:
            proposal_id (int): proposal id
            has_approval (bool): Approved
            voter_address (str): Approve address

        """

        # If the address of the sender is not specified, we prescribe the default
        if voter_address is None:
            voter_address = self.stabila.default_address.hex

        if not self.stabila.isAddress(voter_address):
            raise StabilaError('Invalid voter_address address provided')

        if not is_integer(proposal_id) or proposal_id < 0:
            raise StabilaError('Invalid proposal_id provided')

        if not is_boolean(has_approval):
            raise StabilaError('Invalid has_approval provided')

        return self.stabila.manager.request('/wallet/proposalapprove', {
            'owner_address': self.stabila.address.to_hex(voter_address),
            'proposal_id': int(proposal_id),
            'is_add_approval': bool(has_approval)
        })

    def delete_proposal(self, proposal_id: int, issuer_address: str = None):
        """Delete proposal

        Args:
            proposal_id (int): proposal id
            issuer_address (str): delete the person's address

        Results:
            Delete the proposal's transaction

        """

        # If the address of the sender is not specified, we prescribe the default
        if issuer_address is None:
            issuer_address = self.stabila.default_address.hex

        if not self.stabila.isAddress(issuer_address):
            raise InvalidStabilaError('Invalid issuer_address provided')

        if not isinstance(proposal_id, int) or proposal_id < 0:
            raise InvalidStabilaError('Invalid proposal_id provided')

        return self.stabila.manager.request('/wallet/proposaldelete', {
            'owner_address': self.stabila.address.to_hex(issuer_address),
            'proposal_id': int(proposal_id)
        })

    def update_account(self, account_name, account: str = None):
        """Modify account name

        Note: Username is allowed to edit only once.

        Args:
            account_name (str): name of the account
            account (str): address

        Returns:
            modified Transaction Object

        """

        # If the address of the sender is not specified, we prescribe the default
        if account is None:
            account = self.stabila.default_address.hex

        if not is_string(account_name):
            raise ValueError('Name must be a string')

        if not self.stabila.isAddress(account):
            raise StabilaError('Invalid origin address provided')

        response = self.stabila.manager.request('/wallet/updateaccount', {
            'account_name': self.stabila.toHex(text=account_name),
            'owner_address': self.stabila.address.to_hex(account)
        })

        return response

    def create_smart_contract(self, **kwargs):
        """Deploy Contract

        Deploys a contract.
        Returns TransactionExtention, which contains an unsigned transaction.

        Example:
        .. code-block:: python
            >>> from stabilaapi import Stabila
            >>>
            >>> stabila = Stabila()
            >>> stabila.transaction_builder.create_smart_contract(
            >>>    fee_limit=10**9,
            >>>    call_value=0,
            >>>    consume_user_resource_percent=10
            >>> )

        Args:
            **kwargs: Transaction parameters for the deployment
            transaction as a dict

        """

        if 'bytecode' not in kwargs:
            raise ValueError(
                "Cannot deploy a contract that does not have 'bytecode' associated "
                "with it"
            )

        # Maximum STB consumption, measured in UNIT (1 STB = 1,000,000 UNIT).
        fee_limit = kwargs.setdefault('fee_limit', 0)
        # The same as User Pay Ratio.
        # The percentage of resources specified for users who use this contract.
        # This field accepts integers between [0, 100].
        user_fee_percentage = kwargs.setdefault('consume_user_resource_percent', 0)
        # Amount of STB transferred with this transaction, measured in UNIT (1STB = 1,000,000 UNIT)
        call_value = kwargs.setdefault('call_value', 0)
        # Contract owner address, converted to a hex string
        owner_address = kwargs.setdefault('owner_address', self.stabila.default_address.hex)
        # The max ucr which will be consumed by the owner
        # in the process of excution or creation of the contract,
        # is an integer which should be greater than 0.
        origin_ucr_limit = kwargs.setdefault('origin_ucr_limit', 10000000)

        if not is_integer(user_fee_percentage) and not user_fee_percentage:
            user_fee_percentage = 100

        if not is_hex(kwargs.get('bytecode')):
            raise ValueError('Invalid bytecode provided')

        if not is_integer(fee_limit) or fee_limit <= 0 or \
                fee_limit > 1000000000:
            raise ValueError('Invalid fee limit provided')

        if not is_integer(call_value) or call_value < 0:
            raise ValueError('Invalid call value provided')

        if not is_integer(user_fee_percentage) or user_fee_percentage < 0 or \
                user_fee_percentage > 100:
            raise ValueError('Invalid user fee percentage provided')

        if not is_integer(origin_ucr_limit) or origin_ucr_limit < 0:
            return ValueError('Invalid origin_ucr_limit provided')

        if not self.stabila.isAddress(owner_address):
            raise InvalidAddress('Invalid issuer address provided')

        # We write all the results in one object
        transaction = dict(**kwargs)
        transaction.setdefault('owner_address', self.stabila.address.to_hex(owner_address))

        return self.stabila.manager.request('/wallet/deploycontract',
                                         transaction)

    def trigger_smart_contract(self, **kwargs):
        """Trigger Smart Contract
        Calls a function on a contract

        Args:
            **kwargs: Fill in the required parameters

        Examples:
            >>> stabila = Stabila()
            >>> stabila.transaction_builder.trigger_smart_contract(
            >>>     contract_address='413c8143e98b3e2fe1b1a8fb82b34557505a752390',
            >>>     function_selector='set(uint256,uint256)',
            >>>     fee_limit=30000,
            >>>     call_value=0,
            >>>     parameters=[
            >>>        {'type': 'int256', 'value': 1},
            >>>        {'type': 'int256', 'value': 1}
    ]
)

        Returns:
            TransactionExtention, TransactionExtention contains unsigned Transaction
        """

        contract_address = kwargs.setdefault('contract_address', None)
        function_selector = kwargs.setdefault('function_selector', None)
        parameters = kwargs.setdefault('parameters', [])
        issuer_address = kwargs.setdefault('issuer_address', self.stabila.default_address.hex)
        call_value = kwargs.setdefault('call_value', 0)
        fee_limit = kwargs.setdefault('fee_limit', 1000000000)
        token_value = kwargs.setdefault('token_value', 0)
        token_id = kwargs.setdefault('token_id', 0)

        if not is_integer(token_value) or token_value < 0:
            raise ValueError('Invalid options.tokenValue provided')

        if not is_integer(token_id) or token_id < 0:
            raise ValueError('Invalid options.tokenId provided')

        if not self.stabila.isAddress(contract_address):
            raise InvalidAddress('Invalid contract address provided')

        if not is_string(function_selector):
            raise ValueError('Invalid function selector provided')

        if not is_integer(call_value) or call_value < 0:
            raise ValueError('Invalid call value provided')

        if not is_integer(fee_limit) or fee_limit <= 0 or fee_limit > 1000000000:
            raise ValueError('Invalid fee limit provided')

        function_selector = function_selector.replace('/\s*/g', '')

        if len(parameters) > 0:
            types = []
            values = []
            for abi in parameters:
                if 'type' not in abi or not is_string(abi['type']):
                    raise ValueError('Invalid parameter type provided: ' + abi['type'])

                if abi['type'] == 'address':
                    abi['value'] = self.stabila.address.to_hex(abi['value']).replace('41', '0x', 1)

                types.append(abi['type'])
                values.append(abi['value'])

            try:
                parameters = encode_hex(encode_abi(types, values)).replace('0x', '', 2)
            except ValueError as ex:
                print(ex)

        else:
            parameters = ''

        data = {
            'contract_address': self.stabila.address.to_hex(contract_address),
            'owner_address': self.stabila.address.to_hex(issuer_address),
            'function_selector': function_selector,
            'fee_limit': int(fee_limit),
            'call_value': int(call_value),
            'parameter': parameters
        }

        if token_value:
            data['call_token_value'] = int(token_value)

        if token_id:
            data['token_id'] = int(token_id)

        return self.stabila.manager.request('/wallet/triggersmartcontract', data)

    def create_stb_exchange(self,
                            token_name: str,
                            token_balance: int,
                            stb_balance: int,
                            account: str = None):
        """Create an exchange between a token and STB.
        Token Name should be a CASE SENSITIVE string.
        Note: PLEASE VERIFY THIS ON STABILASCAN.

        Args:
            token_name (str): Token Name
            token_balance (int): balance of the first token
            stb_balance (int): balance of the second token
            account (str): Owner Address
        """

        # If the address of the sender is not specified, we prescribe the default
        if account is None:
            account = self.stabila.default_address.hex

        if not self.stabila.isAddress(account):
            raise StabilaError('Invalid address provided')

        if token_balance <= 0 or stb_balance <= 0:
            raise StabilaError('Invalid amount provided')

        return self.stabila.manager.request('/wallet/exchangecreate', {
            'owner_address': self.stabila.address.to_hex(account),
            'first_token_id': self.stabila.toHex(text=token_name),
            'first_token_balance': token_balance,
            'second_token_id': '5f',
            'second_token_balance': stb_balance
        })

    def create_token_exchange(self,
                              first_token_name: str,
                              first_token_balance: int,
                              second_token_name: str,
                              second_token_balance: int,
                              owner_address: str = None):
        """Create an exchange between a token and another token.
        DO NOT USE THIS FOR STB.
        Token Names should be a CASE SENSITIVE string.

        Args:
            first_token_name (str): the id of the first token
            first_token_balance (int): balance of the first token
            second_token_name (str): the id of the second token
            second_token_balance (int): balance of the second token
            owner_address: owner address

        """
        if owner_address is None:
            owner_address = self.stabila.default_address.hex

        if not self.stabila.isAddress(owner_address):
            raise InvalidAddress('Invalid address provided')

        if second_token_balance <= 0 or first_token_balance <= 0:
            raise ValueError('Invalid amount provided')

        return self.stabila.manager.request('/wallet/exchangecreate', {
            'owner_address': self.stabila.address.to_hex(owner_address),
            'first_token_id': self.stabila.toHex(text=first_token_name),
            'first_token_balance': first_token_balance,
            'second_token_id': self.stabila.toHex(text=second_token_name),
            'second_token_balance': second_token_balance
        })

    def inject_exchange_tokens(self,
                               exchange_id: int,
                               token_name: str,
                               token_amount: int = 0,
                               owner_address: str = None):
        """Adds tokens into a bancor style exchange.
        Will add both tokens at market rate.

        Args:
            exchange_id (int): non-negative integer exchange id
            token_name (str): token name
            token_amount (int): amount of token
            owner_address (str): token owner address in hex

        """
        if owner_address is None:
            owner_address = self.stabila.default_address.hex

        if not self.stabila.isAddress(owner_address):
            raise InvalidAddress('Invalid owner_address provided')

        if exchange_id < 0:
            raise ValueError('Invalid exchange_id provided')

        if token_amount < 1:
            raise ValueError('Invalid token_amount provided')

        return self.stabila.manager.request('/wallet/exchangeinject', {
            'owner_address': self.stabila.address.to_hex(owner_address),
            'exchange_id': exchange_id,
            'token_id': self.stabila.toHex(text=token_name),
            'quant': token_amount
        })

    def create_token(self, **kwargs):
        """Issue Token

        Issuing a token on the STABILA Protocol can be done by anyone
        who has at least 1024 STB in their account.
        When a token is issued it will be shown on the token overview page.
        Users can then participate within the issuing time and exchange their
        STB for tokens.After issuing the token your account will
        receive the amount of tokens equal to the total supply.
        When other users exchange their STB for tokens then the tokens
        will be withdrawn from your account and you will receive
        STB equal to the specified exchange rate.


        Args:
            **kwargs: Fill in the required parameters

        Examples:

            >>> start_func = datetime.now()
            >>> start = int(start_func.timestamp() * 1000)
            >>>
            >>> end_func = datetime.now() + timedelta(days=2)
            >>> end = int(end_func.timestamp() * 1000)
            >>>
            >>> opt = {
            >>>     'name': 'Stabila',
            >>>     'abbreviation': 'STB',
            >>>     'description': 'Hello World',
            >>>     'url': 'https://github.com',
            >>>     'totalSupply': 25000000,
            >>>     'cdedAmount': 1,
            >>>     'cdedDuration': 2,
            >>>     'freeBandwidth': 10000,
            >>>     'freeBandwidthLimit': 10000,
            >>>     'saleStart': start,
            >>>     'saleEnd': end,
            >>>     'voteScore': 1
            >>> }

        """
        issuer_address = kwargs.setdefault(
            'issuer_address', self.stabila.default_address.hex
        )

        if not self.stabila.isAddress(issuer_address):
            raise StabilaError('Invalid issuer address provided')

        total_supply = kwargs.setdefault('totalSupply', 0)
        stb_ratio = kwargs.setdefault('stbRatio', 1)
        token_ratio = kwargs.setdefault('tokenRatio', 1)
        sale_start = kwargs.setdefault(
            'saleStart', START_DATE
        )
        free_bandwidth = kwargs.setdefault('freeBandwidth', 0)
        free_bandwidth_limit = kwargs.setdefault('freeBandwidthLimit', 0)
        cded_amount = kwargs.setdefault('cdedAmount', 0)
        cded_duration = kwargs.setdefault('cdedDuration', 0)
        vote_score = kwargs.setdefault('voteScore', 0)
        precision = kwargs.setdefault('precision', 0)

        if not is_string(kwargs.get('name')):
            raise ValueError('Invalid token name provided')

        if not is_string(kwargs.get('abbreviation')):
            raise ValueError('Invalid token abbreviation provided')

        if not is_integer(total_supply) or total_supply <= 0:
            raise ValueError('Invalid supply amount provided')

        if not is_integer(stb_ratio) or stb_ratio <= 0:
            raise ValueError('STB ratio must be a positive integer')

        if not is_integer(token_ratio) or token_ratio <= 0:
            raise ValueError('Token ratio must be a positive integer')

        if not is_integer(vote_score) or vote_score <= 0:
            raise ValueError('voteScore must be a positive integer greater than 0')

        if not is_integer(precision) or precision <= 0 or precision > 6:
            raise ValueError('precision must be a positive integer > 0 and <= 6')

        if not is_integer(sale_start) or sale_start < START_DATE:
            raise ValueError('Invalid sale start timestamp provided')

        if not is_integer(kwargs.get('saleEnd')) or \
                kwargs.get('saleEnd') <= sale_start:
            raise ValueError('Invalid sale end timestamp provided')

        if not is_string(kwargs.get('description')):
            raise ValueError('Invalid token description provided')

        if not is_valid_url(kwargs.get('url')):
            raise ValueError('Invalid token url provided')

        if not is_integer(free_bandwidth) or free_bandwidth < 0:
            raise ValueError('Invalid free bandwidth amount provided')

        if not is_integer(free_bandwidth_limit) or free_bandwidth_limit < 0 \
                or (free_bandwidth and not free_bandwidth_limit):
            raise ValueError('Invalid free bandwidth limit provided')

        if not is_integer(cded_amount) or cded_amount < 0 \
                or (not cded_duration and cded_amount):
            raise ValueError('Invalid cded supply provided')

        if not is_integer(cded_duration) or cded_duration < 0 \
                or (cded_duration and not cded_amount):
            raise ValueError('Invalid cded duration provided')

        cded_supply = {
            'cded_amount': int(cded_amount),
            'cded_days': int(cded_duration)
        }

        response = self.stabila.manager.request('/wallet/createassetissue', {
            'owner_address': self.stabila.address.to_hex(issuer_address),
            'name': self.stabila.toHex(text=kwargs.get('name')),
            'abbr': self.stabila.toHex(text=kwargs.get('abbreviation')),
            'description': self.stabila.toHex(text=kwargs.get('description')),
            'url': self.stabila.toHex(text=kwargs.get('url')),
            'total_supply': int(total_supply),
            'stb_num': int(stb_ratio),
            'num': int(token_ratio),
            'start_time': int(sale_start),
            'end_time': int(kwargs.get('saleEnd')),
            'free_asset_net_limit': int(free_bandwidth),
            'public_free_asset_net_limit': int(free_bandwidth_limit),
            'cded_supply': cded_supply,
            'vote_score': vote_score,
            'precision': precision
        })

        return response

    def withdraw_exchange_tokens(self,
                                 exchange_id: int,
                                 token_name: str,
                                 token_amount: int = 0,
                                 owner_address: str = None):
        """Withdraws tokens from a bancor style exchange.
        Will withdraw at market rate both tokens.

        Args:
            exchange_id (int): non-negative integer exchange id
            token_name (str): token name
            token_amount (int): number of tokens withdraw
            owner_address (str): owner address in hex

        """
        if owner_address is None:
            owner_address = self.stabila.default_address.hex

        if not self.stabila.isAddress(owner_address):
            raise InvalidAddress('Invalid owner_address provided')

        if exchange_id < 0:
            raise ValueError('Invalid exchange_id provided')

        if token_amount < 1:
            raise ValueError('Invalid token_amount provided')

        return self.stabila.manager.request('/wallet/exchangewithdraw', {
            'owner_address': self.stabila.address.to_hex(owner_address),
            'exchange_id': exchange_id,
            'token_id': self.stabila.toHex(text=token_name),
            'quant': token_amount
        })

    def trade_exchange_tokens(self,
                              exchange_id: int,
                              token_name: str,
                              token_amount_sold: int = 0,
                              token_amount_expected: int = 0,
                              owner_address: str = None):
        """Trade tokens on a bancor style exchange.
        Expected value is a validation and used to cap the total amt of token 2 spent.

        Args:
            exchange_id (int): non-negative integer exchange id
            token_name (str): token name
            token_amount_sold (int): amount f token actually sold
            token_amount_expected (int): amount of token expected
            owner_address (str): token owner address in hex

        """

        if owner_address is None:
            owner_address = self.stabila.default_address.hex

        if not self.stabila.isAddress(owner_address):
            raise InvalidAddress('Invalid owner_address provided')

        if exchange_id < 0:
            raise ValueError('Invalid exchange_id provided')

        if token_amount_sold < 1:
            raise ValueError('Invalid token_amount_sold provided')

        if token_amount_expected < 1:
            raise ValueError('Invalid token_amount_expected provided')

        return self.stabila.manager.request('/wallet/exchangewithdraw', {
            'owner_address': self.stabila.address.to_hex(owner_address),
            'exchange_id': exchange_id,
            'token_id': self.stabila.toHex(text=token_name),
            'quant': token_amount_sold,
            'expected': token_amount_expected
        })

    def update_setting(self,
                       contract_address,
                       user_fee_percentage,
                       owner_address: str = None):
        """Update userFeePercentage.

        Args:
            contract_address (str): the address of the contract to be modified
            user_fee_percentage (int): the percentage of resources specified for users using this contract
            owner_address (str): is the address of the creator

        Returns:
            Contains unsigned transaction Transaction
        """

        if owner_address is None:
            owner_address = self.stabila.default_address.hex

        if not self.stabila.isAddress(owner_address):
            raise InvalidAddress('Invalid owner_address provided')

        if not self.stabila.isAddress(contract_address):
            raise InvalidAddress('Invalid contract_address provided')

        if not is_integer(user_fee_percentage) or user_fee_percentage < 0 or \
                user_fee_percentage > 100:
            raise ValueError('Invalid user_fee_percentage provided')

        return self.stabila.manager.request('wallet/updatesetting', {
            'owner_address': self.stabila.address.to_hex(owner_address),
            'contract_address': self.stabila.address.to_hex(contract_address),
            'consume_user_resource_percent': user_fee_percentage
        })

    def update_ucr_limit(self,
                            contract_address,
                            origin_ucr_limit,
                            owner_address: str = None):
        """Update ucr limit.

        Args:
            contract_address (str): The address of the contract to be modified
            origin_ucr_limit (int): The maximum ucr set by the creator that is created
            owner_address (str): Is the address of the creator

        Returns:
            Contains unsigned transaction Transaction
        """

        if owner_address is None:
            owner_address = self.stabila.default_address.hex

        if not self.stabila.isAddress(owner_address):
            raise InvalidAddress('Invalid owner_address provided')

        if not self.stabila.isAddress(contract_address):
            raise InvalidAddress('Invalid contractAddress provided')

        if not is_integer(origin_ucr_limit) or origin_ucr_limit < 0 or \
                origin_ucr_limit > 10000000:
            raise ValueError('Invalid originUcrLimit  provided')

        return self.stabila.manager.request('wallet/updateucrlimit', {
            'owner_address': self.stabila.address.to_hex(owner_address),
            'contract_address': self.stabila.address.to_hex(contract_address),
            'origin_ucr_limit': origin_ucr_limit
        })

    def check_permissions(self, permissions, _type):
        if permissions is not None:
            if permissions['type'] != _type or \
                    not permissions['permission_name'] or \
                    not is_string(permissions['permission_name']) or \
                    not is_integer(permissions['threshold']) or \
                    permissions['threshold'] < 1 or not permissions['keys']:
                return False

        for key in permissions['key']:
            if not self.stabila.isAddress(key['address']) or \
                    not is_integer(key['weight']) or \
                    key['weight'] > permissions['threshold'] or \
                    key['weight'] < 1 or _type == 2 and not permissions['operations']:
                return False

        return True

    def update_account_permissions(self, owner_address=None,
                                   owner_permissions=None,
                                   witness_permissions=None,
                                   actives_permissions=None
                                   ):
        """Role: update user permissions (for multi-signature)

        Args:
            owner_address (str): The address of the account whose permissions are to be modified
            owner_permissions: Modified owner permission
            witness_permissions: Modified witness permission (if it is a witness)
            actives_permissions: Modified actives permission
        """

        if owner_address is None:
            owner_address = self.stabila.default_address.hex

        if not self.check_permissions(owner_permissions, 0):
            raise InvalidStabilaError('Invalid ownerPermissions provided')

        if not self.check_permissions(witness_permissions, 1):
            raise InvalidStabilaError('Invalid witnessPermissions provided')

        for actives_permission in actives_permissions:
            if not self.check_permissions(actives_permission, 2):
                raise InvalidStabilaError('Invalid activesPermissions provided')

        data = {
            owner_address: owner_address
        }

        if owner_permissions:
            data['owner'] = owner_permissions

        if witness_permissions:
            data['witness'] = witness_permissions

        if actives_permissions:
            if len(actives_permissions) == 1:
                data['actives'] = actives_permissions[0]
            else:
                data['actives'] = actives_permissions

        return self.stabila.manager.request('wallet/accountpermissionupdate', data)
