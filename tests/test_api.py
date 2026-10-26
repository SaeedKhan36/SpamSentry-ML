def test_analyze_persists_and_updates_stats(client):
    response = client.post("/api/analyze", json={"subject": "Hello there", "body": "Let's meet at the office tomorrow."})
    assert response.status_code == 201
    result = response.json()
    assert result["verdict"] == "safe"
    assert client.get("/api/analyses/" + result["id"]).json() == result
    assert client.get("/api/stats").json()["total"] == 1
    assert client.get("/api/analyses?q=hello&verdict=safe").json()["total"] == 1
    assert client.get("/api/analyses?verdict=spam").json()["total"] == 0


def test_reject_empty_and_oversized_input(client):
    for body in ["", "   ", "a" * 50001]:
        assert client.post("/api/analyze", json={"body": body}).status_code == 422
    assert client.get("/api/analyses/missing").status_code == 404
    assert client.get("/api/analyses?limit=0").status_code == 422


def test_import_eml_and_plain_text(client):
    content = b"From: Alex <alex@example.com>\r\nSubject: Team lunch\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSee you tomorrow."
    response = client.post("/api/import", files={"file": ("sample.eml", content, "message/rfc822")})
    assert response.status_code == 200
    assert response.json()["subject"] == "Team lunch"
    assert response.json()["body"] == "See you tomorrow."
    assert client.post("/api/import", files={"file": ("note.txt", b"Hello there", "text/plain")}).status_code == 200
    assert client.post("/api/import", files={"file": ("note.html", b"bad", "text/html")}).status_code == 400
    assert client.post("/api/import", files={"file": ("huge.txt", b"x" * 100001, "text/plain")}).status_code == 413
    assert client.post("/api/import", files={"file": ("empty.txt", b" ", "text/plain")}).status_code == 400


def test_csv_export_neutralizes_formulas(client):
    client.post("/api/analyze", json={"subject": '=HYPERLINK("https://evil.example")', "body": "Hello there"})
    response = client.get("/api/export")
    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert "'=HYPERLINK" in response.text


def test_search_treats_wildcards_as_literal_text(client):
    client.post("/api/analyze", json={"subject": "Save 50% today", "body": "A simple note."})
    client.post("/api/analyze", json={"subject": "Other message", "body": "Another note."})
    assert client.get("/api/analyses", params={"q": "%"}).json()["total"] == 1


def test_ui_and_rules_are_served(client):
    assert client.get("/").status_code == 200
    assert "A second look." in client.get("/").text
    assert client.get("/auth/login").status_code == 200
    assert client.get("/auth/register").status_code == 200
    assert client.get("/auth/login/factor-one").status_code == 200
    assert "dashboard-locked" in client.get("/dashboard").text
    assert client.get("/static/app.js").status_code == 200
    assert len(client.get("/api/rules").json()["rules"]) == 13
