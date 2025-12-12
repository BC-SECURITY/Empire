from pathlib import Path

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
