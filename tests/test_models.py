from athena.models import Objective


def test_objective_serialization_keeps_status_and_created_at_separate():
    objective = Objective(id="OBJ-1", text="secure the project", created_at="2026-09-11T00:00:00+00:00")
    assert objective.status == "active"
    assert objective.created_at == "2026-09-11T00:00:00+00:00"
    assert objective.to_dict()["status"] == "active"
