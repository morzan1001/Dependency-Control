"""Analytics API package - aggregates routers from focused submodules."""

from app.api.router import CustomAPIRouter

from . import (
    dependencies,
    recommendations,
    risk,
    search,
    summary,
    update_frequency,
)

router = CustomAPIRouter()
router.include_router(summary.router)
router.include_router(dependencies.router)
router.include_router(risk.router)
router.include_router(search.router)
router.include_router(recommendations.router)
router.include_router(update_frequency.router)

__all__ = ["router"]
