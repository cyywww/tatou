import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from unittest.mock import MagicMock, patch
from server import app, create_app

# Fixtures
@pytest.fixture
def client():
    """Provide a Flask test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def mock_rmap():
    """
    Intercept and replace app.rmap_handler with a Mock object,
    ensuring tests can run independently without real PGP keys and config.
    """
    original_handler = app.rmap_handler
    mock_handler = MagicMock()
    app.rmap_handler = mock_handler
    yield mock_handler
    # Restore the original handler after the test
    app.rmap_handler = original_handler


# /api/rmap-initiate Endpoint Tests
def test_rmap_initiate_not_configured(client):
    """Test defensive logic when RMAP is not configured."""
    original_handler = app.rmap_handler
    app.rmap_handler = None
    
    response = client.post("/api/rmap-initiate", json={"payload": "dummy"})
    assert response.status_code == 503
    assert "RMAP not configured" in response.get_json()["error"]
    
    app.rmap_handler = original_handler

def test_rmap_initiate_missing_payload(client, mock_rmap):
    """Test the case where the request is missing a payload."""
    response = client.post("/api/rmap-initiate", json={})
    assert response.status_code == 400
    assert "Missing payload" in response.get_json()["error"]

def test_rmap_initiate_success(client, mock_rmap):
    """Test the normal Message 1 processing flow."""
    mock_rmap.handle_message1.return_value = {"payload": "mocked_encrypted_response"}
    
    response = client.post("/api/rmap-initiate", json={"payload": "mocked_encrypted_request"})
    
    assert response.status_code == 200
    assert response.get_json() == {"payload": "mocked_encrypted_response"}
    mock_rmap.handle_message1.assert_called_once_with({"payload": "mocked_encrypted_request"})

def test_rmap_initiate_rmap_error(client, mock_rmap):
    """Test handling when the RMAP library raises a logical error."""
    mock_rmap.handle_message1.return_value = {"error": "Invalid client signature or format"}
    
    response = client.post("/api/rmap-initiate", json={"payload": "bad_payload"})
    
    assert response.status_code == 401
    assert response.get_json() == {"error": "Invalid client signature or format"}


# /api/rmap-get-link Endpoint Tests
def test_rmap_get_link_not_configured(client):
    """Test defensive logic when RMAP is not configured."""
    original_handler = app.rmap_handler
    app.rmap_handler = None
    
    response = client.post("/api/rmap-get-link", json={"payload": "dummy"})
    assert response.status_code == 503
    
    app.rmap_handler = original_handler

def test_rmap_get_link_missing_payload(client, mock_rmap):
    """Test the case where the request is missing a payload."""
    response = client.post("/api/rmap-get-link", json={})
    assert response.status_code == 400

def test_rmap_get_link_rmap_error(client, mock_rmap):
    """Test the case where an error occurs parsing Message 2."""
    mock_rmap.handle_message2.return_value = {"error": "nonceServer does not match"}
    
    response = client.post("/api/rmap-get-link", json={"payload": "invalid_payload"})
    
    assert response.status_code == 401
    assert "nonceServer does not match" in response.get_json()["error"]

def test_rmap_get_link_missing_result(client, mock_rmap):
    """Test the exception case where the RMAP return structure is missing 'result'."""
    mock_rmap.handle_message2.return_value = {"weird_field": "123"}
    
    response = client.post("/api/rmap-get-link", json={"payload": "payload"})
    
    assert response.status_code == 500
    assert "Invalid response from RMAP" in response.get_json()["error"]

def test_rmap_initiate_exception(client, mock_rmap):
    """Test unexpected crashes at the outermost layer of rmap_initiate."""
    mock_rmap.handle_message1.side_effect = Exception("Unexpected server error")
    
    response = client.post("/api/rmap-initiate", json={"payload": "valid"})
    assert response.status_code == 500
    assert "Unexpected server error" in response.get_json()["error"]

def test_rmap_get_link_exception(client, mock_rmap):
    """Test unexpected crashes at the outermost layer of rmap_get_link."""
    mock_rmap.handle_message2.side_effect = Exception("Unexpected server error")
    
    response = client.post("/api/rmap-get-link", json={"payload": "valid"})
    assert response.status_code == 500
    assert "Unexpected server error" in response.get_json()["error"]

def test_rmap_get_link_full_success_and_watermark(client, mock_rmap, tmp_path):
    """Test the complete success flow: link generation, database processing, and watermarked PDF creation."""
    nonce_client = 123456789
    nonce_server = 987654321
    combined = (nonce_client << 64) | nonce_server
    link_hex = f"{combined:032x}"
    
    mock_rmap.handle_message2.return_value = {"result": link_hex}
    mock_rmap.nonces = {"TestIdentity": (nonce_client, nonce_server)}

    # 1. Mock database engine (to avoid real connection failures)
    from unittest.mock import MagicMock
    from server import app
    mock_engine = MagicMock()
    mock_conn = MagicMock()
    mock_engine.begin.return_value.__enter__.return_value = mock_conn
    app.config["_ENGINE"] = mock_engine

    # Simulate the first query (no existing watermarked version found)
    mock_result_1 = MagicMock()
    mock_result_1.first.return_value = None  
    # Simulate the second query (retrieve Document ID)
    mock_result_2 = MagicMock()
    mock_result_2.first.return_value = MagicMock(id=42)
    # Set the return values for SQL execution in sequence
    mock_conn.execute.side_effect = [mock_result_1, mock_result_2, MagicMock()]

    # 2. Mock storage directory and source PDF
    app.config["STORAGE_DIR"] = tmp_path
    source_pdf_dir = tmp_path / "rmap_watermark_pdf"
    source_pdf_dir.mkdir(parents=True)
    source_pdf_path = source_pdf_dir / "group_06_rmap.pdf"
    source_pdf_path.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")

    # Execute request
    response = client.post("/api/rmap-get-link", json={"payload": "valid_msg2_payload"})
    
    assert response.status_code == 200
    assert response.get_json() == {"result": link_hex}

    # Verify that the watermarked file was successfully generated
    wm_dir = tmp_path / "rmap_watermarks"
    wm_file = wm_dir / f"rmap_{link_hex}.pdf"
    assert wm_file.exists()
    assert len(wm_file.read_bytes()) > 10

def test_rmap_get_link_existing(client, mock_rmap):
    """Test the scenario where the requested watermarked version already exists in the database."""
    mock_rmap.handle_message2.return_value = {"result": "fake_link_hex"}

    from unittest.mock import MagicMock
    from server import app
    mock_engine = MagicMock()
    mock_conn = MagicMock()
    mock_engine.begin.return_value.__enter__.return_value = mock_conn
    app.config["_ENGINE"] = mock_engine

    mock_result = MagicMock()
    mock_result.first.return_value = {"path": "/fake/path"}  # Simulate existing record in DB
    mock_conn.execute.return_value = mock_result

    response = client.post("/api/rmap-get-link", json={"payload": "valid"})
    assert response.status_code == 200
    assert response.get_json() == {"result": "fake_link_hex"}

def test_rmap_get_link_missing_source(client, mock_rmap, tmp_path):
    """Test the scenario where the source PDF file cannot be found."""
    mock_rmap.handle_message2.return_value = {"result": "fake_link_hex"}

    from unittest.mock import MagicMock
    from server import app
    mock_engine = MagicMock()
    mock_conn = MagicMock()
    mock_engine.begin.return_value.__enter__.return_value = mock_conn
    app.config["_ENGINE"] = mock_engine

    mock_result = MagicMock()
    mock_result.first.return_value = None
    mock_conn.execute.return_value = mock_result

    # Provide an empty test directory and intentionally skip creating the source file
    app.config["STORAGE_DIR"] = tmp_path 

    response = client.post("/api/rmap-get-link", json={"payload": "valid"})
    assert response.status_code == 404
    assert "Source document not available" in response.get_json()["error"]


# init_rmap() Internal Logic Tests
def test_init_rmap_missing_private_key(tmp_path, monkeypatch):
    """Test that it logs an error and returns None when the private key file is missing."""
    # Mock the environment variable, pointing STORAGE_DIR to the temporary empty directory provided by pytest.
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path))
    
    # Create a new app instance to trigger the internal init_rmap().
    test_app = create_app()
    assert test_app.rmap_handler is None

def test_init_rmap_missing_public_key(tmp_path, monkeypatch):
    """Test that it logs an error and returns None when there is a private key but the public key is missing."""
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path))
    
    pki_dir = tmp_path / "pki"
    pki_dir.mkdir()
    (pki_dir / "g6.asc").write_text("fake_private_key")
    
    test_app = create_app()
    assert test_app.rmap_handler is None

@patch("server.IdentityManager")
@patch("server.RMAP")
def test_init_rmap_success(mock_rmap_class, mock_im_class, tmp_path, monkeypatch):
    """Test successful RMAP initialization when all keys are present."""
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path))
    
    pki_dir = tmp_path / "pki"
    pki_dir.mkdir()
    (pki_dir / "g6.asc").write_text("fake_private_key")
    (pki_dir / "Group_06.asc").write_text("fake_public_key")
    
    mock_rmap_instance = MagicMock()
    mock_rmap_class.return_value = mock_rmap_instance
    
    test_app = create_app()
    
    mock_im_class.assert_called_once_with(
        client_keys_dir=str(pki_dir),
        server_public_key_path=str(pki_dir / "Group_06.asc"),
        server_private_key_path=str(pki_dir / "g6.asc"),
        server_private_key_passphrase=None
    )
    assert test_app.rmap_handler is mock_rmap_instance

@patch("server.IdentityManager")
def test_init_rmap_exception_handling(mock_im_class, tmp_path, monkeypatch):
    """Test that an exception from IdentityManager is safely caught and returns None."""
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path))
    
    pki_dir = tmp_path / "pki"
    pki_dir.mkdir()
    (pki_dir / "g6.asc").write_text("fake_private_key")
    (pki_dir / "Group_06.asc").write_text("fake_public_key")
    
    mock_im_class.side_effect = Exception("Invalid PGP Key Format")
    
    test_app = create_app()
    assert test_app.rmap_handler is None