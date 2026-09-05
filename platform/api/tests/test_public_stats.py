def test_public_platform_stats_exposes_only_the_aggregate_user_count(client) -> None:
    response = client.get("/api/public/stats")

    assert response.status_code == 200
    assert response.json() == {"registered_users": 1}
