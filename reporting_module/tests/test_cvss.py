from reporting.cvss import score_vector, severity_from_score, suggest_vector_for_type


def test_reference_vector_critical():
    # FIRST.org style critical example
    r = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert r.status == "scored"
    assert r.base_score == 9.8
    assert r.severity == "Critical"


def test_reference_vector_medium_xss_like():
    r = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert r.status == "scored"
    assert r.base_score == 6.1
    assert r.severity == "Medium"


def test_invalid_vector_rejected():
    r = score_vector("CVSS:3.1/AV:N/AC:L")
    assert r.status == "invalid"
    assert r.base_score is None


def test_invalid_metric_value():
    r = score_vector("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert r.status == "invalid"


def test_score_zero_distinct_from_unscored():
    r = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert r.base_score == 0.0
    assert r.severity == "None"
    assert severity_from_score(0.0) == "None"


def test_boundaries():
    assert severity_from_score(0.1) == "Low"
    assert severity_from_score(3.9) == "Low"
    assert severity_from_score(4.0) == "Medium"
    assert severity_from_score(6.9) == "Medium"
    assert severity_from_score(7.0) == "High"
    assert severity_from_score(8.9) == "High"
    assert severity_from_score(9.0) == "Critical"


def test_suggestion_marked_analyst_assessed():
    r = suggest_vector_for_type("xss.reflected", verification_status="probable")
    assert r.status == "scored"
    assert r.provenance == "analyst_assessed"
    assert r.vector is not None
