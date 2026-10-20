from app.api.v1.endpoints.analytics.recommendations import _NOT_SUMMARISED, _SUMMARY_BUCKETS
from app.schemas.recommendation import RecommendationType


def test_every_recommendation_type_is_either_tallied_or_named_as_left_out():
    tallied, left_out = set(_SUMMARY_BUCKETS), set(_NOT_SUMMARISED)

    assert tallied | left_out == set(RecommendationType)
    assert not tallied & left_out
