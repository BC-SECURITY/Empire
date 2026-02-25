from starlette.status import HTTP_200_OK


def test_healthz(client):
    resp = client.get("/healthz")

    assert resp.status_code == HTTP_200_OK
    assert resp.json() == {"status": "ok"}
