import unittest
from unittest.mock import patch, MagicMock
import socket
import network_monitor

class TestNetworkMonitor(unittest.TestCase):

    def setUp(self):
        # Clear the cache before each test
        network_monitor.get_hostname.cache_clear()

    @patch('socket.gethostbyaddr')
    def test_get_hostname_success(self, mock_gethostbyaddr):
        mock_gethostbyaddr.return_value = ('test.google-analytics.com', [], ['192.168.1.10'])
        hostname = network_monitor.get_hostname('192.168.1.10')
        self.assertEqual(hostname, 'test.google-analytics.com')
        mock_gethostbyaddr.assert_called_once_with('192.168.1.10')

        # Test cache
        hostname_cached = network_monitor.get_hostname('192.168.1.10')
        self.assertEqual(hostname_cached, 'test.google-analytics.com')
        # Should still be called only once
        mock_gethostbyaddr.assert_called_once_with('192.168.1.10')

    @patch('socket.gethostbyaddr')
    def test_get_hostname_herror(self, mock_gethostbyaddr):
        mock_gethostbyaddr.side_effect = socket.herror
        hostname = network_monitor.get_hostname('192.168.1.20')
        self.assertEqual(hostname, '192.168.1.20')

    def test_is_telemetry(self):
        self.assertTrue(network_monitor.is_telemetry('google-analytics.com'))
        self.assertTrue(network_monitor.is_telemetry('metrics.example.org'))
        self.assertTrue(network_monitor.is_telemetry('telemetry.mozilla.org'))
        self.assertFalse(network_monitor.is_telemetry('github.com'))
        self.assertFalse(network_monitor.is_telemetry('localhost'))

    @patch('network_monitor.get_hostname')
    @patch('psutil.Process')
    @patch('psutil.net_connections')
    @patch('builtins.print')
    def test_monitor_connections(self, mock_print, mock_net_connections, mock_process, mock_get_hostname):
        # Mock connection object
        conn_mock = MagicMock()
        conn_mock.raddr = ('8.8.8.8', 443)
        conn_mock.laddr = ('192.168.1.5', 54321)
        conn_mock.pid = 1234
        conn_mock.status = 'ESTABLISHED'

        mock_net_connections.return_value = [conn_mock]

        # Mock process
        process_mock = MagicMock()
        process_mock.name.return_value = 'chrome'
        mock_process.return_value = process_mock

        # Mock hostname
        mock_get_hostname.return_value = 'dns.google'

        network_monitor.monitor_connections()

        # Check if print was called with expected formatted string
        # It's difficult to match exactly due to formatting, but we can check if parts are in the calls
        called_args = [args[0] for args, kwargs in mock_print.call_args_list]
        self.assertTrue(any('1234' in arg and 'chrome' in arg and '8.8.8.8' in arg for arg in called_args))

if __name__ == '__main__':
    unittest.main()
