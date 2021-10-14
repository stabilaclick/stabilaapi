# --------------------------------------------------------------------
# Copyright (c) iEXBase. All rights reserved.
# Licensed under the MIT License.
# See License.txt in the project root for license information.
# --------------------------------------------------------------------

import sys

import pkg_resources

from eth_account import Account  # noqa: E402
from stabilaapi.providers.http import HttpProvider  # noqa: E402
from stabilaapi.main import Stabila  # noqa: E402

if sys.version_info < (3, 5):
    raise EnvironmentError("Python 3.5 or above is required")


__version__ = pkg_resources.get_distribution("stabilaapi").version

__all__ = [
    '__version__',
    'HttpProvider',
    'Account',
    'Stabila',
]
