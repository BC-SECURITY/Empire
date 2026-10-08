import io
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, UploadFile
from starlette import status

from empire.server.core.config.config_manager import empire_config
from empire.server.core.download_service import DownloadService


def test__increment_filename(tmp_path):
    path = tmp_path / "test.txt"

    filename, location = DownloadService._increment_filename(path)

    assert filename == "test.txt"
    assert location == path

    path.write_text("test")

    filename, location = DownloadService._increment_filename(path)

    assert filename == "test(1).txt"
    assert location == tmp_path / "test(1).txt"

    location.write_text("test")

    filename, location = DownloadService._increment_filename(path)

    assert filename == "test(2).txt"
    assert location == tmp_path / "test(2).txt"


def test_create_download_from_path(main, session_local, models):
    test_upload = Path(__file__).parent / "test-upload.yaml"
    download_service: DownloadService = main.downloadsv2
    with session_local() as db:
        user = db.query(models.User).first()
        download = download_service.create_download(db, user, test_upload)

        assert download.id > 0
        assert download.filename.startswith("test-upload")
        assert download.filename.endswith(".yaml")
        assert f"downloads/uploads/{user.username}/" in download.location
        assert download.location.endswith(".yaml")

        db.delete(download)


def test_create_download_from_path_no_user(main, session_local):
    test_upload = Path(__file__).parent / "test-upload.yaml"
    download_service: DownloadService = main.downloadsv2
    with session_local() as db:
        download = download_service.create_download(db, None, test_upload)

        location = Path(download.location)
        try:
            assert download.id > 0
            assert download.filename.startswith("test-upload")
            assert (
                location.parent
                == empire_config.directories.downloads / "uploads_system"
            )
            assert location.read_bytes() == test_upload.read_bytes()
        finally:
            db.delete(download)
            location.unlink(missing_ok=True)


def test_create_download_blocks_path_traversal(main, session_local, models):
    """A traversal filename must be rejected, never written outside downloads."""
    download_service: DownloadService = main.downloadsv2
    escaped = Path("/tmp/empire_traversal_probe.txt")
    escaped.unlink(missing_ok=True)
    upload = UploadFile(
        io.BytesIO(b"pwned"),
        filename="../../../../../../../../tmp/empire_traversal_probe.txt",
    )
    with session_local() as db:
        user = db.query(models.User).first()

        with pytest.raises(HTTPException) as exc_info:
            download_service.create_download(db, user, upload)

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert exc_info.value.detail == "Invalid filename."
        assert not escaped.exists(), "traversal file escaped the downloads directory"


def test_create_download_from_text_blocks_path_traversal(main, session_local, models):
    """The text-upload path must reject a traversal filename too."""
    download_service: DownloadService = main.downloadsv2
    escaped = Path("/tmp/empire_text_traversal_probe.txt")
    escaped.unlink(missing_ok=True)
    with session_local() as db:
        user = db.query(models.User).first()

        with pytest.raises(HTTPException) as exc_info:
            download_service.create_download_from_text(
                db,
                user,
                "pwned",
                "../../../../../../../../tmp/empire_text_traversal_probe.txt",
            )

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert exc_info.value.detail == "Invalid filename."
        assert not escaped.exists()


def test_create_download_from_text_blocks_traversal_in_subdirectory(
    main, session_local, models
):
    """The ``subdirectory`` argument must not escape the downloads root.

    ``_secure_upload_location`` validates the filename against an already-composed
    ``base_dir``, so a traversing directory component slipped past it entirely:
    the filename here is perfectly safe. Latent today (``basic_reporting`` is the
    only caller and passes a literal), guarded so it stays that way.
    """
    download_service: DownloadService = main.downloadsv2
    downloads = empire_config.directories.downloads
    escaped = downloads.parent / "empire_subdirectory_traversal_probe"
    shutil.rmtree(escaped, ignore_errors=True)
    with session_local() as db:
        user = db.query(models.User).first()

        with pytest.raises(HTTPException) as exc_info:
            download_service.create_download_from_text(
                db,
                user,
                "pwned",
                "report.csv",
                subdirectory="../../empire_subdirectory_traversal_probe",
            )

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert exc_info.value.detail == "Invalid upload location."
        assert not escaped.exists()


def test_create_download_blocks_traversal_in_username(main, session_local):
    """A traversing username must not escape the downloads root.

    ``base_dir`` is composed from ``user.username``, and any enabled non-admin can
    rename themselves through ``PUT /api/v2/users/{uid}`` -- so this half of the
    same missing check is reachable, not latent. A stub user is used rather than
    renaming a real row, which would race the rest of the suite in the shared
    test database.
    """
    download_service: DownloadService = main.downloadsv2
    downloads = empire_config.directories.downloads
    escaped = downloads.parent / "empire_username_traversal_probe"
    shutil.rmtree(escaped, ignore_errors=True)
    user = SimpleNamespace(username="../../empire_username_traversal_probe")
    upload = UploadFile(io.BytesIO(b"pwned"), filename="avatar.png")
    with session_local() as db:
        with pytest.raises(HTTPException) as exc_info:
            download_service.create_download(db, user, upload)

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert exc_info.value.detail == "Invalid upload location."
        assert not escaped.exists()


def test_create_download_rejects_issue_824_poc(main, session_local, models):
    """Exact proof-of-concept from GitHub issue #824.

    The reported exploit uploads a file named
    ``../../../../../../../../root/.ssh/authorized_keys`` to overwrite the
    server's SSH authorized_keys. It must be rejected before any write, so the
    target path is never touched even when the server runs as root.
    """
    download_service: DownloadService = main.downloadsv2
    poc_filename = "../../../../../../../../root/.ssh/authorized_keys"
    upload = UploadFile(io.BytesIO(b"attacker-key"), filename=poc_filename)
    with session_local() as db:
        user = db.query(models.User).first()

        with pytest.raises(HTTPException) as exc_info:
            download_service.create_download(db, user, upload)

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST


class TestSecureUploadLocation:
    """Direct unit tests for _secure_upload_location against adversarial input."""

    @pytest.fixture(autouse=True)
    def _downloads_root(self, monkeypatch, tmp_path):
        """Anchor the downloads root at ``tmp_path`` so the base dirs below are in-root."""
        monkeypatch.setattr(empire_config.directories, "downloads", tmp_path)

    def test_plain_filename_is_allowed(self, tmp_path):
        location = DownloadService._secure_upload_location(tmp_path, "report.yaml")
        assert location == tmp_path / "report.yaml"

    @pytest.mark.parametrize(
        "filename",
        [
            "../etc/passwd",
            "../../../../../../etc/shadow",
            "../../../../../../../../root/.ssh/authorized_keys",  # issue #824 PoC
            "/etc/passwd",
            "..",
            ".",
            "",
            "foo/bar.txt",
            "..\\..\\windows\\evil.dll",
        ],
    )
    def test_traversal_is_rejected(self, tmp_path, filename):
        with pytest.raises(HTTPException) as exc_info:
            DownloadService._secure_upload_location(tmp_path, filename)
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert exc_info.value.detail == "Invalid filename."

    @pytest.mark.parametrize(
        "relative_base",
        [
            "../../escaped",
            "uploads/../../../../escaped",
        ],
    )
    def test_base_dir_outside_downloads_is_rejected(self, tmp_path, relative_base):
        """A base_dir that escapes the downloads root is rejected before any write.

        Each case must land genuinely outside ``tmp_path``: ``uploads/../escaped``
        is still inside the root, so an under-deep case silently tests nothing.
        """
        with pytest.raises(HTTPException) as exc_info:
            DownloadService._secure_upload_location(
                tmp_path / relative_base, "report.csv"
            )
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert exc_info.value.detail == "Invalid upload location."

    def test_absolute_base_dir_outside_downloads_is_rejected(self, tmp_path):
        with pytest.raises(HTTPException) as exc_info:
            DownloadService._secure_upload_location(Path("/etc"), "report.csv")
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert exc_info.value.detail == "Invalid upload location."

    def test_nul_byte_in_base_dir_is_a_400_not_a_500(self, tmp_path):
        """A null byte in ``base_dir`` is a clean rejection, not an uncaught 500.

        ``base_dir`` is composed from ``user.username``, and ``UserUpdateRequest``
        types it as a bare ``str`` -- so any enabled operator can put a null byte
        in it through ``PUT /api/v2/users/{uid}`` and then upload an avatar.
        ``Path.resolve()`` raises ``ValueError`` on an embedded null, so without
        ``is_path_within`` swallowing it this escapes as a 500.
        """
        with pytest.raises(HTTPException) as exc_info:
            DownloadService._secure_upload_location(
                tmp_path / "uploads" / "a\x00b", "report.csv"
            )
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert exc_info.value.detail == "Invalid upload location."

    @pytest.mark.parametrize(
        "relative_base",
        [
            "uploads/user/vinny",
            "uploads/basic_reporting",
            "uploads_system",
            "uploads/..%2f..",
            "uploads/op/../op",
        ],
    )
    def test_base_dir_inside_downloads_is_allowed(self, tmp_path, relative_base):
        """Permissive-side pin: the shipped layouts, plus two paths that look like
        traversal but stay in-root -- a literal ``..%2f..`` directory name and a
        ``..`` that resolves back inside."""
        base_dir = tmp_path / relative_base
        assert DownloadService._secure_upload_location(base_dir, "report.csv") == (
            base_dir / "report.csv"
        )
