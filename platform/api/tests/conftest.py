from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from intel_platform.auth import Principal, get_principal
from intel_platform.database import Base, get_db
from intel_platform.main import app


@pytest.fixture
def client(tmp_path) -> Generator[TestClient, None, None]:
    engine = create_engine(
        f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False}
    )
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(engine)

    def override_db() -> Generator[Session, None, None]:
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_principal] = lambda: Principal(
        subject="test-user", email="analyst@example.test"
    )
    test_client = TestClient(app)
    test_client.app.state.testing_session = testing_session
    response = test_client.post(
        "/api/v1/legal/acceptance",
        json={
            "accepted": True,
            "terms_version": "1.0",
            "responsible_use_version": "1.0",
        },
    )
    assert response.status_code == 200
    yield test_client
    test_client.close()
    app.dependency_overrides.clear()
    engine.dispose()
