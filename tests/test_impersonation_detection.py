"""
Tests for impersonation detection algorithms

Tests Levenshtein distance and TF-IDF similarity thresholds for detecting
fake accounts and impersonation attempts.
"""

import pytest
import sys
import os
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from tabs.impersonation import ImpersonationTab


class TestImpersonationDetection:
    """Test impersonation detection algorithms"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.impersonation_tab = ImpersonationTab()
        
        # Test data for username similarity
        self.test_usernames = [
            "original_user",
            "original_user_",
            "original_user1",
            "original_user123",
            "originaluser",
            "original_user_fake",
            "completely_different",
            "another_user",
        ]
        
        # Test data for bio similarity
        self.test_bios = [
            "Software engineer from San Francisco",
            "Software engineer from San Francisco!",
            "Software engineer from SF",
            "I'm a software engineer from San Francisco",
            "Completely different bio about cooking",
            "Another bio about travel",
        ]
    
    def test_levenshtein_distance(self):
        """Test Levenshtein distance calculation"""
        # Test exact match
        distance = self.impersonation_tab._levenshtein_distance("test", "test")
        assert distance == 0
        
        # Test single character difference
        distance = self.impersonation_tab._levenshtein_distance("test", "tast")
        assert distance == 1
        
        # Test completely different strings
        distance = self.impersonation_tab._levenshtein_distance("test", "different")
        assert distance > 5
        
        # Test empty strings
        distance = self.impersonation_tab._levenshtein_distance("", "")
        assert distance == 0
        
        distance = self.impersonation_tab._levenshtein_distance("test", "")
        assert distance == 4
    
    def test_username_similarity_detection(self):
        """Test username similarity detection with thresholds"""
        target_username = "original_user"
        
        # Test similar usernames (should be detected)
        similar_usernames = [
            "original_user_",  # Added underscore
            "original_user1",  # Added number
            "original_user123",  # Added numbers
            "originaluser",  # Removed underscore
        ]
        
        for username in similar_usernames:
            similarity = self.impersonation_tab._calculate_username_similarity(
                target_username, username
            )
            assert similarity > 0.7, f"Username {username} should be similar to {target_username}"
        
        # Test different usernames (should not be detected)
        different_usernames = [
            "completely_different",
            "another_user",
            "fake_account",
        ]
        
        for username in different_usernames:
            similarity = self.impersonation_tab._calculate_username_similarity(
                target_username, username
            )
            assert similarity < 0.5, f"Username {username} should not be similar to {target_username}"
    
    def test_bio_similarity_detection(self):
        """Test bio similarity detection using TF-IDF"""
        target_bio = "Software engineer from San Francisco"
        
        # Test similar bios (should be detected)
        similar_bios = [
            "Software engineer from San Francisco!",  # Added punctuation
            "I'm a software engineer from San Francisco",  # Added words
            "Software engineer from SF",  # Abbreviated location
        ]
        
        for bio in similar_bios:
            similarity = self.impersonation_tab._calculate_bio_similarity(
                target_bio, bio
            )
            assert similarity > 0.6, f"Bio '{bio}' should be similar to '{target_bio}'"
        
        # Test different bios (should not be detected)
        different_bios = [
            "Completely different bio about cooking",
            "Another bio about travel",
            "Random text with no similarity",
        ]
        
        for bio in different_bios:
            similarity = self.impersonation_tab._calculate_bio_similarity(
                target_bio, bio
            )
            assert similarity < 0.3, f"Bio '{bio}' should not be similar to '{target_bio}'"
    
    def test_similarity_thresholds(self):
        """Test that similarity thresholds work correctly"""
        # Test username threshold (should be around 0.7)
        username_threshold = 0.7
        
        # Test cases that should be above threshold
        high_similarity_cases = [
            ("user123", "user123_"),
            ("test_account", "test_account1"),
            ("original", "original_"),
        ]
        
        for username1, username2 in high_similarity_cases:
            similarity = self.impersonation_tab._calculate_username_similarity(username1, username2)
            assert similarity >= username_threshold, f"Similarity {similarity} should be >= {username_threshold}"
        
        # Test cases that should be below threshold
        low_similarity_cases = [
            ("user123", "different_user"),
            ("test_account", "fake_account"),
            ("original", "completely_different"),
        ]
        
        for username1, username2 in low_similarity_cases:
            similarity = self.impersonation_tab._calculate_username_similarity(username1, username2)
            assert similarity < username_threshold, f"Similarity {similarity} should be < {username_threshold}"
    
    def test_edge_cases(self):
        """Test edge cases for similarity detection"""
        # Test with very short usernames
        similarity = self.impersonation_tab._calculate_username_similarity("a", "b")
        assert similarity == 0.0  # No similarity for single character differences
        
        # Test with very long usernames
        long_username1 = "a" * 100
        long_username2 = "a" * 99 + "b"
        similarity = self.impersonation_tab._calculate_username_similarity(long_username1, long_username2)
        assert similarity > 0.9  # Should be very similar
        
        # Test with empty strings
        similarity = self.impersonation_tab._calculate_username_similarity("", "")
        assert similarity == 1.0  # Empty strings should be considered identical
        
        similarity = self.impersonation_tab._calculate_username_similarity("test", "")
        assert similarity == 0.0  # Empty string should have no similarity
    
    def test_bio_edge_cases(self):
        """Test edge cases for bio similarity"""
        # Test with empty bios
        similarity = self.impersonation_tab._calculate_bio_similarity("", "")
        assert similarity == 1.0  # Empty bios should be identical
        
        # Test with very short bios
        similarity = self.impersonation_tab._calculate_bio_similarity("hi", "hello")
        assert similarity < 0.5  # Short bios should have low similarity
        
        # Test with identical bios
        bio = "This is a test bio"
        similarity = self.impersonation_tab._calculate_bio_similarity(bio, bio)
        assert similarity == 1.0  # Identical bios should have perfect similarity
    
    @pytest.mark.slow
    def test_performance_with_large_datasets(self):
        """Test performance with larger datasets"""
        import time
        
        # Generate larger test datasets
        usernames = [f"user_{i}" for i in range(100)]
        bios = [f"Bio for user {i} with some content" for i in range(100)]
        
        start_time = time.time()
        
        # Test username similarity performance
        for i in range(10):  # Test subset for performance
            for j in range(i + 1, min(i + 10, len(usernames))):
                similarity = self.impersonation_tab._calculate_username_similarity(
                    usernames[i], usernames[j]
                )
                assert 0 <= similarity <= 1
        
        # Test bio similarity performance
        for i in range(10):  # Test subset for performance
            for j in range(i + 1, min(i + 10, len(bios))):
                similarity = self.impersonation_tab._calculate_bio_similarity(
                    bios[i], bios[j]
                )
                assert 0 <= similarity <= 1
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Should complete within reasonable time (adjust threshold as needed)
        assert execution_time < 5.0, f"Performance test took too long: {execution_time}s"


if __name__ == "__main__":
    pytest.main([__file__])
