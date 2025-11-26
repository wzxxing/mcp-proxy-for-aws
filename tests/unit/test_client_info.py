# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for client info extraction from stdin."""

import pytest
from io import StringIO
from mcp import InitializeRequest
from mcp.types import Implementation, InitializeRequestParams
from mcp_proxy_for_aws.server import DEFAULT_CLIENT_INFO, _initialize_client
from unittest.mock import AsyncMock, Mock, patch


@pytest.mark.asyncio
async def test_client_info_from_valid_initialize_request():
    """Test extracting client info from valid InitializeRequest in stdin."""
    init_request = InitializeRequest(
        method='initialize',
        params=InitializeRequestParams(
            protocolVersion='2024-11-05',
            capabilities={},
            clientInfo=Implementation(name='test-client', version='1.0.0'),
        ),
    )

    mock_stdin = StringIO(init_request.model_dump_json(by_alias=True) + '\n')
    mock_transport = Mock()
    mock_client = Mock()
    mock_client.initialize_result = None

    with patch('sys.stdin', mock_stdin):
        with patch('mcp_proxy_for_aws.server.Client') as mock_client_class:
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

            async with _initialize_client(mock_transport):
                pass

            # Verify Client was called with modified client_info
            call_args = mock_client_class.call_args
            client_info = call_args.kwargs.get('client_info')
            assert client_info is not None
            assert 'test-client via mcp-proxy-for-aws@' in client_info.name


@pytest.mark.asyncio
async def test_client_info_with_empty_stdin():
    """Test when stdin is empty."""
    mock_stdin = StringIO('')
    mock_transport = Mock()
    mock_client = Mock()
    mock_client.initialize_result = None

    with patch('sys.stdin', mock_stdin):
        with patch('mcp_proxy_for_aws.server.Client') as mock_client_class:
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

            async with _initialize_client(mock_transport):
                pass

            # Verify Client was called with default client_info
            call_args = mock_client_class.call_args
            client_info = call_args.kwargs.get('client_info')
            assert client_info == DEFAULT_CLIENT_INFO


@pytest.mark.asyncio
async def test_client_info_with_invalid_json():
    """Test when stdin contains invalid JSON."""
    mock_stdin = StringIO('invalid json\n')
    mock_transport = Mock()
    mock_client = Mock()
    mock_client.initialize_result = None

    with patch('sys.stdin', mock_stdin):
        with patch('mcp_proxy_for_aws.server.Client') as mock_client_class:
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

            async with _initialize_client(mock_transport):
                pass

            # Verify Client was called with default client_info
            call_args = mock_client_class.call_args
            client_info = call_args.kwargs.get('client_info')
            assert client_info == DEFAULT_CLIENT_INFO


@pytest.mark.asyncio
async def test_client_info_with_non_initialize_request():
    """Test when stdin contains valid JSON but not an InitializeRequest."""
    mock_stdin = StringIO('{"method": "other", "params": {}}\n')
    mock_transport = Mock()
    mock_client = Mock()
    mock_client.initialize_result = None

    with patch('sys.stdin', mock_stdin):
        with patch('mcp_proxy_for_aws.server.Client') as mock_client_class:
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

            async with _initialize_client(mock_transport):
                pass

            # Verify Client was called with default client_info
            call_args = mock_client_class.call_args
            client_info = call_args.kwargs.get('client_info')
            assert client_info == DEFAULT_CLIENT_INFO


@pytest.mark.asyncio
async def test_client_info_with_malformed_request():
    """Test InitializeRequest with missing required fields."""
    # Manually create JSON without clientInfo to test validation error handling
    malformed_json = '{"method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}}}\n'

    mock_stdin = StringIO(malformed_json)
    mock_transport = Mock()
    mock_client = Mock()
    mock_client.initialize_result = None

    with patch('sys.stdin', mock_stdin):
        with patch('mcp_proxy_for_aws.server.Client') as mock_client_class:
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

            async with _initialize_client(mock_transport):
                pass

            # Verify Client was called with default client_info due to validation error
            call_args = mock_client_class.call_args
            client_info = call_args.kwargs.get('client_info')
            assert client_info == DEFAULT_CLIENT_INFO


@pytest.mark.asyncio
async def test_default_client_info_values():
    """Test DEFAULT_CLIENT_INFO has expected values."""
    assert DEFAULT_CLIENT_INFO.name == 'mcp-proxy-for-aws'
    assert DEFAULT_CLIENT_INFO.version is not None
    assert len(DEFAULT_CLIENT_INFO.version) > 0
