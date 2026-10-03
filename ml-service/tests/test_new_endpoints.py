import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)



def test_get_model_metrics():
    """Verify /model/metrics returns authentic LightGBM training & test metrics."""
    res = client.get("/model/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "test_metrics" in data
    assert "class_names" in data
    assert len(data["class_names"]) == 15
    assert data["test_metrics"]["accuracy"] > 0.99


def test_get_samples_catalog():
    """Verify /samples/catalog returns metadata for test attack samples."""
    res = client.get("/samples/catalog")
    assert res.status_code == 200
    samples = res.json()
    assert len(samples) >= 6
    expected_ids = {"ddos", "dos-hulk", "portscan", "ssh-patator", "web-attack", "benign"}
    catalog_ids = {s["id"] for s in samples}
    assert expected_ids.issubset(catalog_ids)


def test_upload_traffic_csv():
    """Verify /upload/traffic accepts a supported 78-feature CSV file."""
    sample_csv = ROOT.parents[0] / "frontend" / "public" / "samples" / "cic-ids2017-real-sample.csv"
    assert sample_csv.is_file()

    with open(sample_csv, "rb") as f:
        res = client.post(
            "/upload/traffic",
            files={"file": ("sample.csv", f, "text/csv")},
        )
    assert res.status_code == 200
    results = res.json()
    assert len(results) >= 1
    assert "prediction" in results[0]
    assert "confidence" in results[0]
    assert "explanation" in results[0]
    assert "summary" in results[0]


def test_upload_traffic_pcap():
    """Verify /upload/traffic accepts and parses a PCAP file."""
    import tempfile
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        pkts = [
            IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=50001, dport=80, flags="S", window=65535),
            IP(src="93.184.216.34", dst="192.168.1.50") / TCP(sport=80, dport=50001, flags="SA", window=65535),
            IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=50001, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\n\r\n"),
            IP(src="93.184.216.34", dst="192.168.1.50") / TCP(sport=80, dport=50001, flags="FA"),
        ]
        scapy.wrpcap(str(tmp_path), pkts)

        with open(tmp_path, "rb") as f:
            res = client.post(
                "/upload/traffic",
                files={"file": ("traffic.pcap", f, "application/octet-stream")},
            )
        assert res.status_code == 200
        results = res.json()
        assert len(results) >= 1
        assert "prediction" in results[0]
        assert "confidence" in results[0]
    finally:
        if tmp_path.exists():
            tmp_path.unlink()



def test_upload_traffic_invalid_extension():
    """Verify /upload/traffic rejects unsupported file types."""
    res = client.post(
        "/upload/traffic",
        files={"file": ("sample.txt", io.BytesIO(b"invalid data"), "text/plain")},
    )
    assert res.status_code == 400


def test_upload_traffic_all_sample_csvs():
    """Verify /upload/traffic accepts all authentic CIC-IDS2017 sample CSVs."""
    samples_dir = ROOT.parents[0] / "frontend" / "public" / "samples"
    for sample_name in ["cic-ids2017-ddos-sample.csv", "cic-ids2017-portscan-sample.csv", "cic-ids2017-benign-sample.csv", "cic-ids2017-multi-flow-sample.csv"]:
        sample_path = samples_dir / sample_name
        if sample_path.is_file():
            with open(sample_path, "rb") as f:
                res = client.post(
                    "/upload/traffic",
                    files={"file": (sample_name, f, "text/csv")},
                )
            assert res.status_code == 200
            results = res.json()
            assert len(results) >= 1
            assert "prediction" in results[0]
            assert "confidence" in results[0]


def test_upload_traffic_invalid_csv_schema():
    """Verify /upload/traffic rejects CSVs lacking required 78 features with informative 422 error."""
    bad_csv = b"Name,Age,Salary\nAlice,30,50000\n"
    res = client.post(
        "/upload/traffic",
        files={"file": ("bad_schema.csv", io.BytesIO(bad_csv), "text/csv")},
    )
    assert res.status_code == 422
    assert "missing" in res.json()["detail"].lower()


def test_upload_traffic_empty_file():
    """Verify /upload/traffic rejects empty files with 400 Bad Request."""
    res = client.post(
        "/upload/traffic",
        files={"file": ("empty.csv", io.BytesIO(b""), "text/csv")},
    )
    assert res.status_code == 400
    assert "empty" in res.json()["detail"].lower()


def test_samples_catalog_updated_descriptions():
    """Verify updated descriptions and categories in /samples/catalog."""
    res = client.get("/samples/catalog")
    assert res.status_code == 200
    samples_map = {s["id"]: s for s in res.json()}
    
    assert samples_map["dos-hulk"]["category"] == "Application Layer DoS"
    assert samples_map["dos-hulk"]["description"] == "Application Layer DoS"
    
    assert samples_map["ssh-patator"]["category"] == "Credential Access / Brute Force"
    assert samples_map["ssh-patator"]["description"] == "Credential Access / Brute Force"
    
    assert samples_map["web-attack"]["name"] == "Web Attack (Brute Force / XSS / SQLi)"
    assert samples_map["web-attack"]["category"] == "Web Application Attack"
    assert samples_map["web-attack"]["description"] == "Web Application Attack"


def test_auth_login_demo_user():
    """Verify authentication with seeded demo analyst credentials in H2."""
    res = client.post("/auth/login", json={"username": "analyst_soc", "password": "ThreatXAI#2026"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["user"]["username"] == "analyst_soc"
    assert "password_hash" not in data["user"]
    assert data["token"] is not None


def test_auth_register_and_login():
    """Verify new user registration and subsequent login in H2 Database."""
    import uuid
    uid = uuid.uuid4().hex[:6]
    uname = f"test_analyst_{uid}"
    email = f"test_{uid}@threatxai.soc"
    
    reg_res = client.post(
        "/auth/register",
        json={
            "full_name": "Test Analyst",
            "username": uname,
            "email": email,
            "password": "SecurePassword#2026",
        },
    )
    assert reg_res.status_code == 200
    reg_data = reg_res.json()
    assert reg_data["status"] == "success"
    assert reg_data["user"]["username"] == uname
    assert "password_hash" not in reg_data["user"]

    # Login with newly registered credentials
    login_res = client.post("/auth/login", json={"username": uname, "password": "SecurePassword#2026"})
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["user"]["email"] == email


def test_auth_invalid_credentials():
    """Verify rejected login for bad passwords."""
    res = client.post("/auth/login", json={"username": "analyst_soc", "password": "WrongPassword"})
    assert res.status_code == 401


def test_auth_duplicate_username_rejection():
    """Verify rejection when registering an existing username."""
    res = client.post(
        "/auth/register",
        json={
            "full_name": "Duplicate User",
            "username": "analyst_soc",
            "email": "diff_email@threatxai.soc",
            "password": "Password#123",
        },
    )
    assert res.status_code == 400


if __name__ == "__main__":
    test_get_model_metrics()
    print("[PASS] test_get_model_metrics")
    test_get_samples_catalog()
    print("[PASS] test_get_samples_catalog")
    test_samples_catalog_updated_descriptions()
    print("[PASS] test_samples_catalog_updated_descriptions")
    test_auth_login_demo_user()
    print("[PASS] test_auth_login_demo_user")
    test_auth_register_and_login()
    print("[PASS] test_auth_register_and_login")
    test_auth_invalid_credentials()
    print("[PASS] test_auth_invalid_credentials")
    test_auth_duplicate_username_rejection()
    print("[PASS] test_auth_duplicate_username_rejection")
    test_upload_traffic_csv()
    print("[PASS] test_upload_traffic_csv")
    test_upload_traffic_all_sample_csvs()
    print("[PASS] test_upload_traffic_all_sample_csvs")
    test_upload_traffic_invalid_csv_schema()
    print("[PASS] test_upload_traffic_invalid_csv_schema")
    test_upload_traffic_empty_file()
    print("[PASS] test_upload_traffic_empty_file")
    test_upload_traffic_pcap()
    print("[PASS] test_upload_traffic_pcap")
    test_upload_traffic_invalid_extension()
    print("[PASS] test_upload_traffic_invalid_extension")
    print("=== ALL NEW ENDPOINT TESTS PASSED! ===")


