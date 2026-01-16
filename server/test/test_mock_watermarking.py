"""test_mock_watermarking.py

测试 Mock 水印逻辑，用于验证服务器在水印服务异常时的行为。
"""
import os
import unittest.mock as mock
import pytest
from pathlib import Path
import tempfile
import shutil

# 设置测试模式环境变量（必须在导入 server 之前设置）
os.environ["TEST_MODE"] = "1"

# 导入路径可能因项目结构而异，尝试多种导入方式
try:
    from server import app
except ImportError:
    # 如果上面的导入失败，尝试从 src 导入
    import sys
    from pathlib import Path
    server_src_path = Path(__file__).parent.parent / "src"
    if str(server_src_path) not in sys.path:
        sys.path.insert(0, str(server_src_path))
    from server import app

# Mock 水印函数的返回值控制
_MOCK_WATERMARK_BEHAVIOR = {
    "should_succeed": True,  # 控制是否成功
    "should_raise_exception": False,  # 控制是否抛出异常
    "exception_type": Exception,  # 异常类型
    "exception_message": "Watermarking service crashed",  # 异常消息
    "return_value": b"%PDF-1.4\nMock Watermarked PDF\n%%EOF",  # Mock 返回值
}


def create_mock_apply_watermark(should_succeed=True, exception_type=Exception, exception_message="Watermarking failed"):
    """创建一个可配置的 Mock apply_watermark 函数
    
    Args:
        should_succeed: 是否成功返回
        exception_type: 异常类型（当 should_succeed=False 时使用）
        exception_message: 异常消息
        
    Returns:
        一个 Mock 函数，根据配置返回成功或抛出异常
    """
    def mock_apply_watermark(method, pdf, secret, key, position=None):
        if not should_succeed:
            raise exception_type(exception_message)
        # 返回一个简单的 Mock PDF 字节
        return _MOCK_WATERMARK_BEHAVIOR["return_value"]
    return mock_apply_watermark


def create_mock_read_watermark(should_succeed=True, exception_type=Exception, exception_message="Read watermark failed", return_secret="mock-secret"):
    """创建一个可配置的 Mock read_watermark 函数
    
    Args:
        should_succeed: 是否成功返回
        exception_type: 异常类型（当 should_succeed=False 时使用）
        exception_message: 异常消息
        return_secret: 成功时返回的 secret
        
    Returns:
        一个 Mock 函数，根据配置返回成功或抛出异常
    """
    def mock_read_watermark(method, pdf, key):
        if not should_succeed:
            raise exception_type(exception_message)
        return return_secret
    return mock_read_watermark


def create_mock_is_watermarking_applicable(should_succeed=True):
    """创建一个可配置的 Mock is_watermarking_applicable 函数
    
    Args:
        should_succeed: 是否返回 True（表示适用）
        
    Returns:
        一个 Mock 函数，返回 True 或 False
    """
    def mock_is_watermarking_applicable(method, pdf, position=None):
        return should_succeed
    return mock_is_watermarking_applicable


@pytest.fixture
def temp_storage_dir():
    """创建一个临时存储目录"""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def test_client_with_auth(temp_storage_dir):
    """创建一个测试客户端，并设置认证 token"""
    # 设置存储目录
    app.config["STORAGE_DIR"] = temp_storage_dir
    
    client = app.test_client()
    
    # 创建一个测试用户并登录获取 token
    # 注意：在 TEST_MODE 下，数据库会自动初始化测试用户
    login_response = client.post("/api/login", json={
        "email": "test@example.com",
        "password": "testpass123"
    })
    
    if login_response.status_code == 200:
        token = login_response.get_json()["token"]
        client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
    
    return client


@pytest.fixture
def sample_pdf_file(temp_storage_dir):
    """创建一个示例 PDF 文件"""
    pdf_path = temp_storage_dir / "sample.pdf"
    pdf_path.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")
    return pdf_path


class TestMockWatermarkingSuccess:
    """测试 Mock 水印成功场景"""
    
    def test_create_watermark_success(self, test_client_with_auth, sample_pdf_file, temp_storage_dir):
        """测试水印创建成功时，服务器返回 200/201"""
        # 准备：上传一个文档
        with open(sample_pdf_file, 'rb') as f:
            upload_response = test_client_with_auth.post(
                "/api/upload-document",
                data={"file": (f, "test.pdf"), "name": "test.pdf"},
                content_type="multipart/form-data"
            )
        
        assert upload_response.status_code == 201
        doc_id = upload_response.get_json()["id"]
        
        # Mock 水印函数使其成功
        # 注意：patch 路径应该是实际使用该函数的地方
        with mock.patch('watermarking_utils.apply_watermark', side_effect=create_mock_apply_watermark(should_succeed=True)):
            with mock.patch('watermarking_utils.is_watermarking_applicable', side_effect=create_mock_is_watermarking_applicable(should_succeed=True)):
                # 创建水印
                response = test_client_with_auth.post(
                    "/api/create-watermark",
                    json={
                        "method": "text-overlay",
                        "intended_for": "test@example.com",
                        "secret": "test-secret",
                        "key": "test-key"
                    },
                    query_string={"id": doc_id}
                )
                
                # 验证：应该返回 201 成功
                assert response.status_code == 201
                data = response.get_json()
                assert "link" in data
                assert "id" in data


class TestMockWatermarkingFailure:
    """测试 Mock 水印失败场景"""
    
    def test_create_watermark_service_crash(self, test_client_with_auth, sample_pdf_file):
        """测试水印服务崩溃时，服务器返回 500 错误"""
        # 准备：上传一个文档
        with open(sample_pdf_file, 'rb') as f:
            upload_response = test_client_with_auth.post(
                "/api/upload-document",
                data={"file": (f, "test.pdf"), "name": "test.pdf"},
                content_type="multipart/form-data"
            )
        
        assert upload_response.status_code == 201
        doc_id = upload_response.get_json()["id"]
        
        # Mock 水印函数使其抛出异常（模拟服务崩溃）
        with mock.patch('watermarking_utils.apply_watermark', side_effect=create_mock_apply_watermark(
            should_succeed=False,
            exception_type=RuntimeError,
            exception_message="Watermarking service crashed"
        )):
            with mock.patch('watermarking_utils.is_watermarking_applicable', side_effect=create_mock_is_watermarking_applicable(should_succeed=True)):
                # 创建水印
                response = test_client_with_auth.post(
                    "/api/create-watermark",
                    json={
                        "method": "text-overlay",
                        "intended_for": "test@example.com",
                        "secret": "test-secret",
                        "key": "test-key"
                    },
                    query_string={"id": doc_id}
                )
                
                # 验证：应该返回 500 错误
                assert response.status_code == 500
                data = response.get_json()
                assert "error" in data
                assert "watermarking failed" in data["error"].lower()
    
    def test_create_watermark_value_error(self, test_client_with_auth, sample_pdf_file):
        """测试水印服务返回 ValueError 时的处理"""
        # 准备：上传一个文档
        with open(sample_pdf_file, 'rb') as f:
            upload_response = test_client_with_auth.post(
                "/api/upload-document",
                data={"file": (f, "test.pdf"), "name": "test.pdf"},
                content_type="multipart/form-data"
            )
        
        assert upload_response.status_code == 201
        doc_id = upload_response.get_json()["id"]
        
        # Mock 水印函数使其抛出 ValueError
        with mock.patch('watermarking_utils.apply_watermark', side_effect=create_mock_apply_watermark(
            should_succeed=False,
            exception_type=ValueError,
            exception_message="Invalid PDF format"
        )):
            with mock.patch('watermarking_utils.is_watermarking_applicable', side_effect=create_mock_is_watermarking_applicable(should_succeed=True)):
                # 创建水印
                response = test_client_with_auth.post(
                    "/api/create-watermark",
                    json={
                        "method": "text-overlay",
                        "intended_for": "test@example.com",
                        "secret": "test-secret",
                        "key": "test-key"
                    },
                    query_string={"id": doc_id}
                )
                
                # 验证：应该返回 500 错误
                assert response.status_code == 500
                data = response.get_json()
                assert "error" in data
                assert "watermarking failed" in data["error"].lower()
    
    def test_create_watermark_not_applicable(self, test_client_with_auth, sample_pdf_file):
        """测试水印方法不适用时的处理"""
        # 准备：上传一个文档
        with open(sample_pdf_file, 'rb') as f:
            upload_response = test_client_with_auth.post(
                "/api/upload-document",
                data={"file": (f, "test.pdf"), "name": "test.pdf"},
                content_type="multipart/form-data"
            )
        
        assert upload_response.status_code == 201
        doc_id = upload_response.get_json()["id"]
        
        # Mock is_watermarking_applicable 返回 False
        with mock.patch('watermarking_utils.is_watermarking_applicable', side_effect=create_mock_is_watermarking_applicable(should_succeed=False)):
            # 创建水印
            response = test_client_with_auth.post(
                "/api/create-watermark",
                json={
                    "method": "text-overlay",
                    "intended_for": "test@example.com",
                    "secret": "test-secret",
                    "key": "test-key"
                },
                query_string={"id": doc_id}
            )
            
            # 验证：应该返回 400 错误（方法不适用）
            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
            assert "not applicable" in data["error"].lower()


class TestMockWatermarkingReadFailure:
    """测试 Mock 水印读取失败场景"""
    
    def test_read_watermark_service_crash(self, test_client_with_auth, sample_pdf_file):
        """测试读取水印时服务崩溃的处理"""
        # 准备：上传一个文档
        with open(sample_pdf_file, 'rb') as f:
            upload_response = test_client_with_auth.post(
                "/api/upload-document",
                data={"file": (f, "test.pdf"), "name": "test.pdf"},
                content_type="multipart/form-data"
            )
        
        assert upload_response.status_code == 201
        doc_id = upload_response.get_json()["id"]
        
        # Mock 读取水印函数使其抛出异常
        with mock.patch('watermarking_utils.read_watermark', side_effect=create_mock_read_watermark(
            should_succeed=False,
            exception_type=RuntimeError,
            exception_message="Watermark reading service crashed"
        )):
            # 读取水印
            response = test_client_with_auth.post(
                "/api/read-watermark",
                json={
                    "method": "text-overlay",
                    "key": "test-key"
                },
                query_string={"id": doc_id}
            )
            
            # 验证：应该返回 400 错误（因为 read_watermark 异常被捕获为 "Error when attempting to read watermark"）
            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
    
    def test_read_watermark_success(self, test_client_with_auth, sample_pdf_file):
        """测试读取水印成功场景"""
        # 准备：上传一个文档
        with open(sample_pdf_file, 'rb') as f:
            upload_response = test_client_with_auth.post(
                "/api/upload-document",
                data={"file": (f, "test.pdf"), "name": "test.pdf"},
                content_type="multipart/form-data"
            )
        
        assert upload_response.status_code == 201
        doc_id = upload_response.get_json()["id"]
        
        # Mock 读取水印函数使其成功
        with mock.patch('watermarking_utils.read_watermark', side_effect=create_mock_read_watermark(
            should_succeed=True,
            return_secret="mock-secret-123"
        )):
            # 读取水印
            response = test_client_with_auth.post(
                "/api/read-watermark",
                json={
                    "method": "text-overlay",
                    "key": "test-key"
                },
                query_string={"id": doc_id}
            )
            
            # 验证：应该返回 201 成功
            assert response.status_code == 201
            data = response.get_json()
            assert "secret" in data
            assert data["secret"] == "mock-secret-123"


class TestMockWatermarkingBehaviorControl:
    """测试 Mock 水印行为控制"""
    
    def test_mock_can_be_configured(self):
        """测试 Mock 函数可以根据配置返回不同行为"""
        # 测试成功场景
        mock_func_success = create_mock_apply_watermark(should_succeed=True)
        result = mock_func_success("method", "pdf", "secret", "key")
        assert isinstance(result, bytes)
        assert len(result) > 0
        
        # 测试异常场景
        mock_func_fail = create_mock_apply_watermark(
            should_succeed=False,
            exception_type=ValueError,
            exception_message="Test error"
        )
        with pytest.raises(ValueError, match="Test error"):
            mock_func_fail("method", "pdf", "secret", "key")
    
    def test_mock_read_watermark_configurable(self):
        """测试 Mock read_watermark 函数可以根据配置返回不同行为"""
        # 测试成功场景
        mock_func_success = create_mock_read_watermark(
            should_succeed=True,
            return_secret="custom-secret"
        )
        result = mock_func_success("method", "pdf", "key")
        assert result == "custom-secret"
        
        # 测试异常场景
        mock_func_fail = create_mock_read_watermark(
            should_succeed=False,
            exception_type=KeyError,
            exception_message="Secret not found"
        )
        with pytest.raises(KeyError, match="Secret not found"):
            mock_func_fail("method", "pdf", "key")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

