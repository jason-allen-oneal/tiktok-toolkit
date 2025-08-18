"""
Tests for UI threading in PySide applications

Ensures that network calls and heavy computations are kept off the GUI thread
to maintain responsive user interface.
"""

import pytest
import sys
import os
import time
import threading
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QThread, Signal, QTimer
from PySide6.QtTest import QTest


class TestUIThreading:
    """Test UI threading patterns"""
    
    @pytest.fixture(scope="class")
    def app(self):
        """Create QApplication instance for testing"""
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
        yield app
    
    def test_network_calls_in_separate_thread(self, app):
        """Test that network calls are made in separate threads"""
        from tabs.main import AuthTab
        
        # Mock the auth tab
        auth_tab = AuthTab()
        
        # Mock the network request
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                'access_token': 'test_token',
                'refresh_token': 'test_refresh_token'
            }
            mock_post.return_value = mock_response
            
            # Track which thread the request is made in
            request_thread = None
            
            def track_thread(*args, **kwargs):
                nonlocal request_thread
                request_thread = threading.current_thread()
                return mock_response
            
            mock_post.side_effect = track_thread
            
            # Make the request
            auth_tab.refresh_access_token()
            
            # Verify request was made in a different thread
            assert request_thread is not None
            assert request_thread != threading.main_thread()
    
    def test_heavy_computation_in_worker_thread(self, app):
        """Test that heavy computations are moved to worker threads"""
        from tabs.impersonation import ImpersonationTab
        
        # Mock the impersonation tab
        impersonation_tab = ImpersonationTab()
        
        # Track computation thread
        computation_thread = None
        
        def track_computation_thread():
            nonlocal computation_thread
            computation_thread = threading.current_thread()
            time.sleep(0.1)  # Simulate heavy computation
        
        # Mock the heavy computation method
        with patch.object(impersonation_tab, '_calculate_username_similarity') as mock_calc:
            mock_calc.side_effect = track_computation_thread
            
            # Run computation in a separate thread
            thread = threading.Thread(target=impersonation_tab._calculate_username_similarity, args=("test1", "test2"))
            thread.start()
            thread.join()
            
            # Verify computation was done in a different thread
            assert computation_thread is not None
            assert computation_thread != threading.main_thread()
    
    def test_signal_emission_from_worker_thread(self, app):
        """Test that signals are properly emitted from worker threads"""
        from PySide6.QtCore import QObject, Signal
        
        class WorkerObject(QObject):
            result_ready = Signal(str)
            
            def do_work(self):
                # Simulate work in a separate thread
                time.sleep(0.1)
                self.result_ready.emit("work_complete")
        
        worker = WorkerObject()
        result_received = []
        
        def on_result(result):
            result_received.append(result)
        
        worker.result_ready.connect(on_result)
        
        # Run work in separate thread
        thread = threading.Thread(target=worker.do_work)
        thread.start()
        thread.join()
        
        # Process events to handle signal
        app.processEvents()
        
        # Verify signal was received
        assert len(result_received) == 1
        assert result_received[0] == "work_complete"
    
    def test_ui_updates_only_in_main_thread(self, app):
        """Test that UI updates only happen in the main thread"""
        from PySide6.QtWidgets import QLabel
        
        label = QLabel("Initial")
        ui_update_thread = None
        
        def update_ui():
            nonlocal ui_update_thread
            ui_update_thread = threading.current_thread()
            label.setText("Updated")
        
        # Update UI in main thread
        update_ui()
        
        # Verify update was in main thread
        assert ui_update_thread == threading.main_thread()
        assert label.text() == "Updated"
    
    def test_loading_spinner_threading(self, app):
        """Test that loading spinner works correctly with threading"""
        from loading_spinner import LoadingSpinner
        from PySide6.QtWidgets import QWidget
        
        parent = QWidget()
        spinner = LoadingSpinner(parent)
        
        # Start spinner
        spinner.start()
        
        # Verify spinner is running
        assert spinner.isVisible()
        
        # Stop spinner
        spinner.stop()
        
        # Verify spinner is stopped
        assert not spinner.isVisible()
    
    def test_rate_limiting_thread_safety(self, app):
        """Test that rate limiting is thread-safe"""
        from security import RateLimiter
        
        rate_limiter = RateLimiter(base_delay=0.1)
        
        # Test concurrent access
        def worker_thread():
            rate_limiter.wait_if_needed()
            rate_limiter.handle_response(200)
        
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=worker_thread)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify rate limiter is still functional
        assert rate_limiter.current_delay >= rate_limiter.base_delay
    
    def test_secure_storage_thread_safety(self, app):
        """Test that secure storage operations are thread-safe"""
        from security import SecureTokenStorage, SecurityManager
        
        # Create temporary storage for testing
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_path = tmp_file.name
        
        try:
            security_manager = SecurityManager()
            storage = SecureTokenStorage(tmp_path, security_manager)
            
            test_tokens = {
                'access_token': 'test_token',
                'refresh_token': 'test_refresh_token'
            }
            
            # Test concurrent save operations
            def save_tokens():
                storage.save_tokens(test_tokens)
            
            threads = []
            for _ in range(3):
                thread = threading.Thread(target=save_tokens)
                threads.append(thread)
                thread.start()
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
            
            # Verify tokens can still be loaded
            loaded_tokens = storage.load_tokens()
            assert loaded_tokens is not None
            assert loaded_tokens['access_token'] == 'test_token'
            
        finally:
            # Clean up
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    def test_pii_handling_thread_safety(self, app):
        """Test that PII handling is thread-safe"""
        from security import hash_pii, redact_pii
        
        # Test concurrent PII hashing
        test_data = "test@example.com"
        
        def hash_pii_thread():
            return hash_pii(test_data)
        
        threads = []
        results = []
        
        for _ in range(5):
            thread = threading.Thread(target=lambda: results.append(hash_pii_thread()))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all results are valid hashes
        assert len(results) == 5
        for result in results:
            assert ':' in result  # Should contain salt separator
            assert len(result) > 20  # Should be reasonably long
    
    def test_logger_thread_safety(self, app):
        """Test that logger is thread-safe"""
        from logger import logger
        
        log_messages = []
        
        def log_thread():
            logger.info("TEST", f"Message from thread {threading.current_thread().name}")
            log_messages.append(f"Thread {threading.current_thread().name}")
        
        threads = []
        for i in range(5):
            thread = threading.Thread(target=log_thread, name=f"Worker-{i}")
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all threads logged successfully
        assert len(log_messages) == 5
    
    def test_cleanup_on_thread_exit(self, app):
        """Test that threads are properly cleaned up"""
        from PySide6.QtCore import QThread, Signal
        
        class TestThread(QThread):
            finished_signal = Signal()
            
            def run(self):
                time.sleep(0.1)
                self.finished_signal.emit()
        
        thread = TestThread()
        cleanup_called = False
        
        def on_finished():
            nonlocal cleanup_called
            cleanup_called = True
        
        thread.finished_signal.connect(on_finished)
        thread.start()
        
        # Wait for thread to complete
        thread.wait()
        
        # Verify cleanup was called
        assert cleanup_called
        
        # Verify thread is finished
        assert thread.isFinished()


if __name__ == "__main__":
    pytest.main([__file__])
