import pytest
import json
import base64
from server.src.yuwei_cao_watermark import YuweiCaoWatermark
from server.src.watermarking_method import SecretNotFoundError, InvalidKeyError, WatermarkingError

# Fixtures
@pytest.fixture
def watermark_method():
    """Initialize the watermarking method class."""
    return YuweiCaoWatermark()

@pytest.fixture
def sample_pdf():
    """Provide a very basic valid PDF byte stream for testing."""
    return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"

@pytest.fixture
def secret():
    """Secret message for watermarking."""
    return "This_is_a_top_secret_message_2026"

@pytest.fixture
def key():
    """Encryption key for testing."""
    return "secure_password_123!@"

# Test Cases

def test_get_usage(watermark_method):
    """Test that get_usage returns a correct usage string."""
    usage = watermark_method.get_usage()
    assert isinstance(usage, str)
    assert "Yuwei Cao" in usage

def test_is_watermark_applicable_valid_pdf(watermark_method, sample_pdf):
    """Test that a valid PDF is recognized as applicable."""
    assert watermark_method.is_watermark_applicable(sample_pdf) is True

def test_is_watermark_applicable_invalid_pdf(watermark_method):
    """Test that an invalid PDF (not starting with %PDF-) is recognized as not applicable."""
    # As long as it doesn't start with %PDF-, is_watermark_applicable catches ValueError and returns False.
    invalid_pdf = b"This is just a plain text file, not a pdf."
    assert watermark_method.is_watermark_applicable(invalid_pdf) is False

def test_add_watermark_success(watermark_method, sample_pdf, secret, key):
    """Test successful watermark addition; the output should contain the original PDF and the Magic string."""
    watermarked_pdf = watermark_method.add_watermark(sample_pdf, secret, key)
    
    assert isinstance(watermarked_pdf, bytes)
    assert len(watermarked_pdf) > len(sample_pdf)
    assert watermark_method._MAGIC in watermarked_pdf
    assert watermarked_pdf.startswith(b"%PDF-")

def test_add_watermark_empty_secret_raises_error(watermark_method, sample_pdf, key):
    """Test that a ValueError is raised when the secret is empty."""
    with pytest.raises(ValueError, match="Secret must be a non-empty string"):
        watermark_method.add_watermark(sample_pdf, "", key)

def test_add_watermark_empty_key_raises_error(watermark_method, sample_pdf, secret):
    """Test that a ValueError is raised when the key is empty."""
    with pytest.raises(ValueError, match="Key must be a non-empty string"):
        watermark_method.add_watermark(sample_pdf, secret, "")

def test_read_secret_success(watermark_method, sample_pdf, secret, key):
    """Test the complete lifecycle of reading a watermark (correct reading after addition)."""
    watermarked_pdf = watermark_method.add_watermark(sample_pdf, secret, key)
    extracted_secret = watermark_method.read_secret(watermarked_pdf, key)
    
    assert extracted_secret == secret

def test_read_secret_wrong_key_raises_error(watermark_method, sample_pdf, secret, key):
    """Test that an InvalidKeyError is raised when reading with the wrong password."""
    watermarked_pdf = watermark_method.add_watermark(sample_pdf, secret, key)
    
    with pytest.raises(InvalidKeyError, match="MAC verification failed - incorrect password"):
        watermark_method.read_secret(watermarked_pdf, "Wrong_Password_Here")

def test_read_secret_no_watermark_raises_error(watermark_method, sample_pdf, key):
    """Test that a SecretNotFoundError is raised when reading a PDF without a watermark."""
    with pytest.raises(SecretNotFoundError, match="No Yuwei Cao watermark found in document"):
        watermark_method.read_secret(sample_pdf, key)

def test_read_secret_corrupted_payload(watermark_method, sample_pdf, secret, key):
    """Test that corresponding errors are raised when the watermark payload is tampered with or corrupted."""
    watermarked_pdf = watermark_method.add_watermark(sample_pdf, secret, key)
    
    # Simulate payload corruption: replace valid base64 string with invalid format.
    magic_idx = watermarked_pdf.rfind(watermark_method._MAGIC)
    corrupted_pdf = watermarked_pdf[:magic_idx + len(watermark_method._MAGIC)] + b"INVALID_BASE64_!!!\n"
    
    with pytest.raises(SecretNotFoundError):
        watermark_method.read_secret(corrupted_pdf, key)