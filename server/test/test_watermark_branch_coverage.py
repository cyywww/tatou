"""test_watermark_branch_coverage.py

全面的分支覆盖率测试，针对 create-watermark 和 read-watermark API 端点。
使用 Mock 水印功能来覆盖所有可达的逻辑分支。
"""
import os
import unittest.mock as mock
import pytest
from pathlib import Path
import tempfile
import shutil
from sqlalchemy import text  # 新增引用

# 设置测试模式环境变量（必须在导入 server 之前设置）
os.environ["TEST_MODE"] = "1"

# 导入路径可能因项目结构而异
try:
    from server.src.server import app
except ImportError:
    # 如果上面的导入失败，尝试从 src 导入
    import sys
    from pathlib import Path
    server_src_path = Path(__file__).parent.parent / "src"
    if str(server_src_path) not in sys.path:
        sys.path.insert(0, str(server_src_path))
    # 尝试直接导入 server 模块
    try:
        from server import app
    except ImportError:
        # 如果还是失败，导入 server.py
        import server
        app = server.app


# ============================================================================
# Mock 辅助函数
# ============================================================================

def create_mock_apply_watermark(should_succeed=True, return_empty=False, exception_type=Exception, exception_message="Watermarking failed"):
    """创建 Mock apply_watermark 函数"""
    def mock_apply_watermark(method, pdf, secret, key, position=None):
        if not should_succeed:
            raise exception_type(exception_message)
        if return_empty:
            return b""  # 返回空字节
        return b"%PDF-1.4\nMock Watermarked PDF\n%%EOF"
    return mock_apply_watermark


def create_mock_read_watermark(should_succeed=True, return_secret="mock-secret", exception_type=Exception, exception_message="Read watermark failed"):
    """创建 Mock read_watermark 函数"""
    def mock_read_watermark(method, pdf, key):
        if not should_succeed:
            raise exception_type(exception_message)
        return return_secret
    return mock_read_watermark


def create_mock_is_watermarking_applicable(should_succeed=True, should_raise=False, exception_type=Exception, exception_message="Check failed"):
    """创建 Mock is_watermarking_applicable 函数"""
    def mock_is_watermarking_applicable(method, pdf, position=None):
        if should_raise:
            raise exception_type(exception_message)
        return should_succeed
    return mock_is_watermarking_applicable


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def temp_storage_dir():
    """创建临时存储目录"""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def test_client_with_auth(temp_storage_dir):
    """创建测试客户端并设置认证 token"""
    app.config["STORAGE_DIR"] = temp_storage_dir
    
    # --- 关键修改开始：数据库清理与初始化 ---
    # 强制初始化 engine (如果尚未初始化)
    with app.app_context():
        if app.config.get("_ENGINE") is None:
            # 通过访问 healthz 触发 get_engine
            with app.test_client() as c:
                c.get("/healthz")
        
        engine = app.config.get("_ENGINE")
        if engine:
            # 清空所有表，防止数据冲突 (assert 503 == 201 的根本原因)
            with engine.begin() as conn:
                conn.execute(text("DELETE FROM Versions"))
                conn.execute(text("DELETE FROM Documents"))
                conn.execute(text("DELETE FROM Users"))
    
    client = app.test_client()

    # 重新注册测试用户 (因为刚才把 Users 表清空了)
    client.post("/api/create-user", json={
        "email": "test@example.com",
        "login": "testuser",
        "password": "testpass123"
    })
    # --- 关键修改结束 ---
    
    # 使用测试用户登录
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
    """创建示例 PDF 文件"""
    pdf_path = temp_storage_dir / "files" / "testuser" / "sample.pdf"
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    pdf_path.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")
    return pdf_path


@pytest.fixture
def uploaded_document(test_client_with_auth, sample_pdf_file):
    """上传一个文档并返回文档 ID"""
    with open(sample_pdf_file, 'rb') as f:
        upload_response = test_client_with_auth.post(
            "/api/upload-document",
            data={"file": (f, "test.pdf"), "name": "test.pdf"},
            content_type="multipart/form-data"
        )
    assert upload_response.status_code == 201
    return upload_response.get_json()["id"]


# ============================================================================
# create-watermark 分支覆盖率测试
# ============================================================================

class TestCreateWatermarkBranchCoverage:
    """create-watermark 端点的全面分支覆盖测试"""
    
    # ===== 输入验证分支 =====
    
    def test_create_watermark_missing_document_id(self, test_client_with_auth):
        """分支：document_id 完全缺失"""
        response = test_client_with_auth.post(
            "/api/create-watermark",
            json={
                "method": "text-overlay",
                "intended_for": "test@example.com",
                "secret": "test-secret",
                "key": "test-key"
            }
        )
        assert response.status_code == 400
        assert "document id required" in response.get_json()["error"].lower()
    
    def test_create_watermark_invalid_document_id_type(self, test_client_with_auth):
        """分支：document_id 类型无效（TypeError/ValueError）"""
        response = test_client_with_auth.post(
            "/api/create-watermark",
            json={
                "id": "not-a-number",
                "method": "text-overlay",
                "intended_for": "test@example.com",
                "secret": "test-secret",
                "key": "test-key"
            }
        )
        assert response.status_code == 400
        assert "document id required" in response.get_json()["error"].lower()
    
    def test_create_watermark_document_id_from_path_param(self, test_client_with_auth, uploaded_document):
        """分支：document_id 从路径参数获取"""
        with mock.patch('watermarking_utils.apply_watermark', side_effect=create_mock_apply_watermark(should_succeed=True)):
            with mock.patch('watermarking_utils.is_watermarking_applicable', side_effect=create_mock_is_watermarking_applicable(should_succeed=True)):
                response = test_client_with_auth.post(
                    f"/api/create-watermark/{uploaded_document}",
                    json={
                        "method": "text-overlay",
                        "intended_for": "test@example.com",
                        "secret": "test-secret",
                        "key": "test-key"
                    }
                )
                assert response.status_code == 201
    
    def test_create_watermark_document_id_from_query_param_id(self, test_client_with_auth, uploaded_document):
        """分支：document_id 从查询参数 ?id= 获取"""
        with mock.patch('watermarking_utils.apply_watermark', side_effect=create_mock_apply_watermark(should_succeed=True)):
            with mock.patch('watermarking_utils.is_watermarking_applicable', side_effect=create_mock_is_watermarking_applicable(should_succeed=True)):
                response = test_client_with_auth.post(
                    "/api/create-watermark",
                    json={
                        "method": "text-overlay",
                        "intended_for": "test@example.com",
                        "secret": "test-secret",
                        "key": "test-key"
                    },
                    query_string={"id": uploaded_document}
                )
                assert response.status_code == 201
    
    def test_create_watermark_document_id_from_query_param_documentid(self, test_client_with_auth, uploaded_document):
        """分支：document_id 从查询参数 ?documentid= 获取"""
        with mock.patch('watermarking_utils.apply_watermark', side_effect=create_mock_apply_watermark(should_succeed=True)):
            with mock.patch('watermarking_utils.is_watermarking_applicable', side_effect=create_mock_is_watermarking_applicable(should_succeed=True)):
                response = test_client_with_auth.post(
                    "/api/create-watermark",
                    json={
                        "method": "text-overlay",
                        "intended_for": "test@example.com",
                        "secret": "test-secret",
                        "key": "test-key"
                    },
                    query_string={"documentid": uploaded_document}
                )
                assert response.status_code == 201
    
    def test_create_watermark_document_id_from_json_body(self, test_client_with_auth, uploaded_document):
        """分支：document_id 从 JSON body 获取"""
        with mock.patch('watermarking_utils.apply_watermark', side_effect=create_mock_apply_watermark(should_succeed=True)):
            with mock.patch('watermarking_utils.is_watermarking_applicable', side_effect=create_mock_is_watermarking_applicable(should_succeed=True)):
                response = test_client_with_auth.post(
                    "/api/create-watermark",
                    json={
                        "id": uploaded_document,
                        "method": "text-overlay",
                        "intended_for": "test@example.com",
                        "secret": "test-secret",
                        "key": "test-key"
                    }
                )
                assert response.status_code == 201
    
    def test_create_watermark_missing_method(self, test_client_with_auth, uploaded_document):
        """分支：缺少 method 参数"""
        response = test_client_with_auth.post(
            "/api/create-watermark",
            json={
                "id": uploaded_document,
                "intended_for": "test@example.com",
                "secret": "test-secret",
                "key": "test-key"
            }
        )
        assert response.status_code == 400
        assert "method" in response.get_json()["error"].lower()
    
    def test_create_watermark_missing_intended_for(self, test_client_with_auth, uploaded_document):
        """分支：缺少 intended_for 参数"""
        response = test_client_with_auth.post(
            "/api/create-watermark",
            json={
                "id": uploaded_document,
                "method": "text-overlay",
                "secret": "test-secret",
                "key": "test-key"
            }
        )
        assert response.status_code == 400
    
    def test_create_watermark_secret_not_string(self, test_client_with_auth, uploaded_document):
        """分支：secret 不是字符串类型"""
        response = test_client_with_auth.post(
            "/api/create-watermark",
            json={
                "id": uploaded_document,
                "method": "text-overlay",
                "intended_for": "test@example.com",
                "secret": 123,  # 不是字符串
                "key": "test-key"
            }
        )
        assert response.status_code == 400
    
    def test_create_watermark_key_not_string(self, test_client_with_auth, uploaded_document):
        """分支：key 不是字符串类型"""
        response = test_client_with_auth.post(
            "/api/create-watermark",
            json={
                "id": uploaded_document,
                "method": "text-overlay",
                "intended_for": "test@example.com",
                "secret": "test-secret",
                "key": None  # 不是字符串
            }
        )
        assert response.status_code == 400
    
    # ===== 数据库查询分支 =====
    
    def test_create_watermark_document_not_found(self, test_client_with_auth):
        """分支：文档不存在"""
        with mock.patch('watermarking_utils.apply_watermark', side_effect=create_mock_apply_watermark(should_succeed=True)):
            response = test_client_with_auth.post(
                "/api/create-watermark",
                json={
                    "id": 99999,  # 不存在的文档 ID
                    "method": "text-overlay",
                    "intended_for": "test@example.com",
                    "secret": "test-secret",
                    "key": "test-key"
                }
            )
            assert response.status_code == 404
            assert "document not found" in response.get_json()["error"].lower()
    
    def test_create_watermark_database_error_on_query(self, test_client_with_auth, uploaded_document):
        """分支：数据库查询异常"""
        # 由于 get_engine 是内部函数，我们需要 mock app.config 中的 _ENGINE
        original_engine = app.config.get("_ENGINE")
        
        # 创建一个会抛出异常的 mock engine
        mock_engine = mock.MagicMock()
        mock_conn = mock.MagicMock()
        mock_conn.__enter__ = mock.MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = mock.MagicMock(return_value=None)
        mock_conn.execute.side_effect = Exception("Database connection failed")
        mock_engine.connect.return_value = mock_conn
        mock_engine.begin.return_value = mock_conn
        
        app.config["_ENGINE"] = mock_engine
        try:
            response = test_client_with_auth.post(
                "/api/create-watermark",
                json={
                    "id": uploaded_document,
                    "method": "text-overlay",
                    "intended_for": "test@example.com",
                    "secret": "test-secret",
                    "key": "test-key"
                }
            )
            assert response.status_code == 503
            assert "database error" in response.get_json()["error"].lower()
        finally:
            # 恢复原始 engine
            app.config["_ENGINE"] = original_engine
    
    # ===== 路径处理分支 =====
    
    def test_create_watermark_path_invalid(self, test_client_with_auth, uploaded_document, temp_storage_dir):
        """分支：路径解析失败（RuntimeError）"""
        # 注入一个会导致路径解析失败的路径
        from sqlalchemy import text
        # 通过 app.config 获取 engine（get_engine 是内部函数，无法直接导入）
        engine = app.config.get("_ENGINE")
        if engine is None:
            # 如果 engine 还未创建，触发一次数据库查询来初始化
            test_client_with_auth.get("/healthz")
            engine = app.config.get("_ENGINE")
        
        with engine.begin() as conn:
            # 更新文档路径为一个会导致 RuntimeError 的路径
            conn.execute(
                text("UPDATE Documents SET path = :path WHERE id = :id"),
                {"path": "../../../etc/passwd", "id": uploaded_document}
            )
        
        response = test_client_with_auth.post(
            "/api/create-watermark",
            json={
                "id": uploaded_document,
                "method": "text-overlay",
                "intended_for": "test@example.com",
                "secret": "test-secret",
                "key": "test-key"
            }
        )
        assert response.status_code == 500
        assert "path invalid" in response.get_json()["error"].lower()
    
    def test_create_watermark_file_missing(self, test_client_with_auth, uploaded_document, temp_storage_dir):
        """分支：文件不存在"""
        # 删除文件但保留数据库记录
        from sqlalchemy import text
        # 通过 app.config 获取 engine
        engine = app.config.get("_ENGINE")
        if engine is None:
            test_client_with_auth.get("/healthz")
            engine = app.config.get("_ENGINE")
        
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT path FROM Documents WHERE id = :id"),
                {"id": uploaded_document}
            ).first()
            if row and Path(row.path).exists():
                Path(row.path).unlink()
        
        response = test_client_with_auth.post(
            "/api/create-watermark",
            json={
                "id": uploaded_document,
                "method": "text-overlay",
                "intended_for": "test@example.com",
                "secret": "test-secret",
                "key": "test-key"
            }
        )
        assert response.status_code == 410
        assert "file missing" in response.get_json()["error"].lower()
    
    # ===== 水印适用性检查分支 =====
    
    def test_create_watermark_method_not_applicable(self, test_client_with_auth, uploaded_document):
        """分支：水印方法不适用（返回 False）"""
        with mock.patch('watermarking_utils.is_watermarking_applicable', side_effect=create_mock_is_watermarking_applicable(should_succeed=False)):
            response = test_client_with_auth.post(
                "/api/create-watermark",
                json={
                    "id": uploaded_document,
                    "method": "text-overlay",
                    "intended_for": "test@example.com",
                    "secret": "test-secret",
                    "key": "test-key"
                }
            )
            assert response.status_code == 400
            assert "not applicable" in response.get_json()["error"].lower()
    
    def test_create_watermark_applicability_check_exception(self, test_client_with_auth, uploaded_document):
        """分支：水印适用性检查抛出异常"""
        with mock.patch('watermarking_utils.is_watermarking_applicable', side_effect=create_mock_is_watermarking_applicable(
            should_succeed=False,
            should_raise=True,
            exception_type=ValueError,
            exception_message="PDF parsing failed"
        )):
            response = test_client_with_auth.post(
                "/api/create-watermark",
                json={
                    "id": uploaded_document,
                    "method": "text-overlay",
                    "intended_for": "test@example.com",
                    "secret": "test-secret",
                    "key": "test-key"
                }
            )
            assert response.status_code == 400
            assert "applicability check failed" in response.get_json()["error"].lower()
    
    # ===== 水印应用分支 =====
    
    def test_create_watermark_apply_empty_output(self, test_client_with_auth, uploaded_document):
        """分支：apply_watermark 返回空字节"""
        with mock.patch('watermarking_utils.apply_watermark', side_effect=create_mock_apply_watermark(should_succeed=True, return_empty=True)):
            with mock.patch('watermarking_utils.is_watermarking_applicable', side_effect=create_mock_is_watermarking_applicable(should_succeed=True)):
                response = test_client_with_auth.post(
                    "/api/create-watermark",
                    json={
                        "id": uploaded_document,
                        "method": "text-overlay",
                        "intended_for": "test@example.com",
                        "secret": "test-secret",
                        "key": "test-key"
                    }
                )
                assert response.status_code == 500
                assert "no output" in response.get_json()["error"].lower()
    
    def test_create_watermark_apply_exception(self, test_client_with_auth, uploaded_document):
        """分支：apply_watermark 抛出异常"""
        with mock.patch('watermarking_utils.apply_watermark', side_effect=create_mock_apply_watermark(
            should_succeed=False,
            exception_type=RuntimeError,
            exception_message="Watermarking service crashed"
        )):
            with mock.patch('watermarking_utils.is_watermarking_applicable', side_effect=create_mock_is_watermarking_applicable(should_succeed=True)):
                response = test_client_with_auth.post(
                    "/api/create-watermark",
                    json={
                        "id": uploaded_document,
                        "method": "text-overlay",
                        "intended_for": "test@example.com",
                        "secret": "test-secret",
                        "key": "test-key"
                    }
                )
                assert response.status_code == 500
                assert "watermarking failed" in response.get_json()["error"].lower()
    
    # ===== 文件写入分支 =====
    
    def test_create_watermark_file_write_failure(self, test_client_with_auth, uploaded_document, temp_storage_dir):
        """分支：文件写入失败"""
        with mock.patch('watermarking_utils.apply_watermark', side_effect=create_mock_apply_watermark(should_succeed=True)):
            with mock.patch('watermarking_utils.is_watermarking_applicable', side_effect=create_mock_is_watermarking_applicable(should_succeed=True)):
                # Mock Path.open 使其抛出异常
                with mock.patch('pathlib.Path.open', side_effect=IOError("Permission denied")):
                    response = test_client_with_auth.post(
                        "/api/create-watermark",
                        json={
                            "id": uploaded_document,
                            "method": "text-overlay",
                            "intended_for": "test@example.com",
                            "secret": "test-secret",
                            "key": "test-key"
                        }
                    )
                    assert response.status_code == 500
                    assert "failed to write" in response.get_json()["error"].lower()
    
    # ===== 数据库插入分支 =====
    
    def test_create_watermark_database_insert_failure(self, test_client_with_auth, uploaded_document, temp_storage_dir):
        """分支：数据库插入失败"""
        with mock.patch('watermarking_utils.apply_watermark', side_effect=create_mock_apply_watermark(should_succeed=True)):
            with mock.patch('watermarking_utils.is_watermarking_applicable', side_effect=create_mock_is_watermarking_applicable(should_succeed=True)):
                # 先正常查询文档，然后让插入失败
                from sqlalchemy import text
                engine = app.config.get("_ENGINE")
                
                # 确保文档存在
                with engine.connect() as conn:
                    row = conn.execute(
                        text("SELECT path FROM Documents WHERE id = :id"),
                        {"id": uploaded_document}
                    ).first()
                
                # Mock 数据库插入失败
                original_begin = engine.begin
                call_count = [0]
                
                def mock_begin():
                    call_count[0] += 1
                    if call_count[0] == 1:  # 插入时失败
                        mock_conn = mock.MagicMock()
                        mock_conn.__enter__ = mock.MagicMock(return_value=mock_conn)
                        mock_conn.__exit__ = mock.MagicMock(return_value=None)
                        mock_conn.execute.side_effect = Exception("Database insert failed")
                        return mock_conn
                    return original_begin()
                
                with mock.patch.object(engine, 'begin', side_effect=mock_begin):
                    response = test_client_with_auth.post(
                        "/api/create-watermark",
                        json={
                            "id": uploaded_document,
                            "method": "text-overlay",
                            "intended_for": "test@example.com",
                            "secret": "test-secret",
                            "key": "test-key"
                        }
                    )
                    # 注意：由于 Mock 的复杂性，这个测试可能需要调整
                    # 如果 Mock 不工作，我们可以通过其他方式测试这个分支
                    assert response.status_code in [500, 503]
    
    # ===== 成功分支 =====
    
    def test_create_watermark_success(self, test_client_with_auth, uploaded_document):
        """分支：成功创建水印"""
        with mock.patch('watermarking_utils.apply_watermark', side_effect=create_mock_apply_watermark(should_succeed=True)):
            with mock.patch('watermarking_utils.is_watermarking_applicable', side_effect=create_mock_is_watermarking_applicable(should_succeed=True)):
                response = test_client_with_auth.post(
                    "/api/create-watermark",
                    json={
                        "id": uploaded_document,
                        "method": "text-overlay",
                        "intended_for": "test@example.com",
                        "secret": "test-secret",
                        "key": "test-key"
                    }
                )
                assert response.status_code == 201
                data = response.get_json()
                assert "link" in data
                assert "id" in data


# ============================================================================
# read-watermark 分支覆盖率测试
# ============================================================================

class TestReadWatermarkBranchCoverage:
    """read-watermark 端点的全面分支覆盖测试"""
    
    # ===== 输入验证分支 =====
    
    def test_read_watermark_missing_document_id(self, test_client_with_auth):
        """分支：document_id 完全缺失"""
        response = test_client_with_auth.post(
            "/api/read-watermark",
            json={
                "method": "text-overlay",
                "key": "test-key"
            }
        )
        assert response.status_code == 400
        assert "document id required" in response.get_json()["error"].lower()
    
    def test_read_watermark_invalid_document_id_type(self, test_client_with_auth):
        """分支：document_id 类型无效"""
        response = test_client_with_auth.post(
            "/api/read-watermark",
            json={
                "id": "invalid",
                "method": "text-overlay",
                "key": "test-key"
            }
        )
        assert response.status_code == 400
    
    def test_read_watermark_document_id_from_path_param(self, test_client_with_auth, uploaded_document):
        """分支：document_id 从路径参数获取"""
        with mock.patch('watermarking_utils.read_watermark', side_effect=create_mock_read_watermark(should_succeed=True)):
            response = test_client_with_auth.post(
                f"/api/read-watermark/{uploaded_document}",
                json={
                    "method": "text-overlay",
                    "key": "test-key"
                }
            )
            assert response.status_code == 201
    
    def test_read_watermark_document_id_from_query_param(self, test_client_with_auth, uploaded_document):
        """分支：document_id 从查询参数获取"""
        with mock.patch('watermarking_utils.read_watermark', side_effect=create_mock_read_watermark(should_succeed=True)):
            response = test_client_with_auth.post(
                "/api/read-watermark",
                json={
                    "method": "text-overlay",
                    "key": "test-key"
                },
                query_string={"id": uploaded_document}
            )
            assert response.status_code == 201
    
    def test_read_watermark_missing_method(self, test_client_with_auth, uploaded_document):
        """分支：缺少 method 参数"""
        response = test_client_with_auth.post(
            "/api/read-watermark",
            json={
                "id": uploaded_document,
                "key": "test-key"
            }
        )
        assert response.status_code == 400
        assert "method" in response.get_json()["error"].lower()
    
    def test_read_watermark_missing_key(self, test_client_with_auth, uploaded_document):
        """分支：缺少 key 参数"""
        response = test_client_with_auth.post(
            "/api/read-watermark",
            json={
                "id": uploaded_document,
                "method": "text-overlay"
            }
        )
        assert response.status_code == 400
    
    def test_read_watermark_key_not_string(self, test_client_with_auth, uploaded_document):
        """分支：key 不是字符串类型"""
        response = test_client_with_auth.post(
            "/api/read-watermark",
            json={
                "id": uploaded_document,
                "method": "text-overlay",
                "key": 123
            }
        )
        assert response.status_code == 400
    
    # ===== 数据库查询分支 =====
    
    def test_read_watermark_document_not_found(self, test_client_with_auth):
        """分支：文档不存在"""
        response = test_client_with_auth.post(
            "/api/read-watermark",
            json={
                "id": 99999,
                "method": "text-overlay",
                "key": "test-key"
            }
        )
        assert response.status_code == 404
    
    def test_read_watermark_database_error(self, test_client_with_auth, uploaded_document):
        """分支：数据库查询异常"""
        # Mock app.config 中的 _ENGINE
        original_engine = app.config.get("_ENGINE")
        
        mock_engine = mock.MagicMock()
        mock_conn = mock.MagicMock()
        mock_conn.__enter__ = mock.MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = mock.MagicMock(return_value=None)
        mock_conn.execute.side_effect = Exception("Database error")
        mock_engine.connect.return_value = mock_conn
        
        app.config["_ENGINE"] = mock_engine
        try:
            response = test_client_with_auth.post(
                "/api/read-watermark",
                json={
                    "id": uploaded_document,
                    "method": "text-overlay",
                    "key": "test-key"
                }
            )
            assert response.status_code == 503
        finally:
            app.config["_ENGINE"] = original_engine
    
    # ===== 路径处理分支 =====
    
    def test_read_watermark_path_invalid(self, test_client_with_auth, uploaded_document):
        """分支：路径解析失败"""
        from sqlalchemy import text
        engine = app.config.get("_ENGINE")
        if engine is None:
            test_client_with_auth.get("/healthz")
            engine = app.config.get("_ENGINE")
        
        with engine.begin() as conn:
            conn.execute(
                text("UPDATE Documents SET path = :path WHERE id = :id"),
                {"path": "../../../etc/passwd", "id": uploaded_document}
            )
        
        response = test_client_with_auth.post(
            "/api/read-watermark",
            json={
                "id": uploaded_document,
                "method": "text-overlay",
                "key": "test-key"
            }
        )
        assert response.status_code == 500
    
    def test_read_watermark_file_missing(self, test_client_with_auth, uploaded_document):
        """分支：文件不存在"""
        from sqlalchemy import text
        engine = app.config.get("_ENGINE")
        if engine is None:
            test_client_with_auth.get("/healthz")
            engine = app.config.get("_ENGINE")
        
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT path FROM Documents WHERE id = :id"),
                {"id": uploaded_document}
            ).first()
            if row and Path(row.path).exists():
                Path(row.path).unlink()
        
        response = test_client_with_auth.post(
            "/api/read-watermark",
            json={
                "id": uploaded_document,
                "method": "text-overlay",
                "key": "test-key"
            }
        )
        assert response.status_code == 410
    
    # ===== 水印读取分支 =====
    
    def test_read_watermark_read_exception(self, test_client_with_auth, uploaded_document):
        """分支：read_watermark 抛出异常"""
        with mock.patch('watermarking_utils.read_watermark', side_effect=create_mock_read_watermark(
            should_succeed=False,
            exception_type=ValueError,
            exception_message="Invalid watermark format"
        )):
            response = test_client_with_auth.post(
                "/api/read-watermark",
                json={
                    "id": uploaded_document,
                    "method": "text-overlay",
                    "key": "test-key"
                }
            )
            assert response.status_code == 400
            assert "error when attempting to read watermark" in response.get_json()["error"].lower()
    
    # ===== 成功分支 =====
    
    def test_read_watermark_success(self, test_client_with_auth, uploaded_document):
        """分支：成功读取水印"""
        with mock.patch('watermarking_utils.read_watermark', side_effect=create_mock_read_watermark(
            should_succeed=True,
            return_secret="extracted-secret-123"
        )):
            response = test_client_with_auth.post(
                "/api/read-watermark",
                json={
                    "id": uploaded_document,
                    "method": "text-overlay",
                    "key": "test-key"
                }
            )
            assert response.status_code == 201
            data = response.get_json()
            assert data["secret"] == "extracted-secret-123"
            assert data["documentid"] == uploaded_document


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=server.src.server", "--cov-branch"])