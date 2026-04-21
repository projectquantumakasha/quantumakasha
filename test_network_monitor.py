import unittest
from unittest.mock import patch, MagicMock
import socket
import network_monitor

class TestNetworkMonitor(unittest.TestCase):

    def setUp(self):
        # Clear the lru_cache before each test to ensure predictable results
        network_monitor.get_host_by_addr.cache_clear()

    @patch('network_monitor.socket.gethostbyaddr')
    def test_get_host_by_addr_success(self, mock_gethostbyaddr):
        mock_gethostbyaddr.return_value = ('example.com', [], ['1.2.3.4'])
        host = network_monitor.get_host_by_addr('1.2.3.4')
        self.assertEqual(host, 'example.com')
        mock_gethostbyaddr.assert_called_once_with('1.2.3.4')

    @patch('network_monitor.socket.gethostbyaddr')
    def test_get_host_by_addr_herror(self, mock_gethostbyaddr):
        mock_gethostbyaddr.side_effect = socket.herror
        host = network_monitor.get_host_by_addr('1.2.3.4')
        self.assertEqual(host, 'Unknown')

    @patch('network_monitor.socket.gethostbyaddr')
    def test_get_host_by_addr_exception(self, mock_gethostbyaddr):
        mock_gethostbyaddr.side_effect = Exception("Test error")
        host = network_monitor.get_host_by_addr('1.2.3.4')
        self.assertEqual(host, 'Error')

    def test_is_telemetry(self):
        self.assertTrue(network_monitor.is_telemetry("data.1e100.net"))
        self.assertTrue(network_monitor.is_telemetry("telemetry.microsoft.com"))
        self.assertTrue(network_monitor.is_telemetry("metrics.apple.com"))
        self.assertFalse(network_monitor.is_telemetry("github.com"))
        self.assertFalse(network_monitor.is_telemetry("Unknown"))

    @patch('network_monitor.psutil.net_connections')
    @patch('network_monitor.psutil.Process')
    @patch('network_monitor.get_host_by_addr')
    @patch('sys.stdout', new_callable=MagicMock)
    def test_monitor_connections(self, mock_stdout, mock_get_host_by_addr, mock_process, mock_net_connections):
        # Mock connections
        conn1 = MagicMock()
        conn1.status = 'ESTABLISHED'
        conn1.pid = 1234
        conn1.laddr.ip = '192.168.1.10'
        conn1.laddr.port = 50000
        conn1.raddr.ip = '8.8.8.8'
        conn1.raddr.port = 443

        conn2 = MagicMock()
        conn2.status = 'ESTABLISHED'
        conn2.pid = 5678
        conn2.laddr.ip = '192.168.1.10'
        conn2.laddr.port = 50001
        conn2.raddr.ip = '1.2.3.4'
        conn2.raddr.port = 80

        mock_net_connections.return_value = [conn1, conn2]

        # Mock process names
        def mock_proc_init(pid):
            proc = MagicMock()
            if pid == 1234:
                proc.name.return_value = 'chrome'
            else:
                proc.name.return_value = 'python'
            return proc

        mock_process.side_effect = mock_proc_init

        # Mock host resolution
        def mock_resolve(ip):
            if ip == '8.8.8.8':
                return 'dns.google'
            elif ip == '1.2.3.4':
                return 'telemetry.example.com'
            return 'Unknown'

        mock_get_host_by_addr.side_effect = mock_resolve

        # Capture output
        import io
        import sys
        captured_output = io.StringIO()
        sys.stdout = captured_output

        network_monitor.monitor_connections()

        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()

        # Assertions on the output
        self.assertIn('1234', output)
        self.assertIn('chrome', output)
        self.assertIn('BROWSER', output) # Should be flagged as browser

        self.assertIn('5678', output)
        self.assertIn('python', output)
        self.assertIn('TELEMETRY', output) # Should be flagged as telemetry

if __name__ == '__main__':
    unittest.main()
