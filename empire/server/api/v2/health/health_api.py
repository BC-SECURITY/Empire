from empire.server.api.api_router import APIRouter

router = APIRouter(
    prefix="",
    tags=["admin"],
)


@router.get("/healthz")
def health_check():
    return {"status": "ok"}
