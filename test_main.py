import pytest
from io import StringIO
from collections import defaultdict
from main import LogAnalyzer, HandlersReport, ReportFactory

@pytest.fixture
def sample_log_data():
    return {
        "/api/v1/users/": {"DEBUG": 10, "INFO": 20},
        "/api/v1/products/": {"INFO": 15, "WARNING": 5},
    }

def test_parse_log_line():
    line = '2023-01-01 12:00:00 django.request : DEBUG "GET /api/v1/test/"'
    assert LogAnalyzer.parse_log_line(line) == ("/api/v1/test/", "DEBUG")
    
    line = "not a request log"
    assert LogAnalyzer.parse_log_line(line) is None

def test_handlers_report_generate(sample_log_data):
    report = HandlersReport.generate(sample_log_data)
    assert "HANDLER" in report
    assert "/api/v1/users/" in report
    assert "/api/v1/products/" in report
    assert "Total requests: 50" in report  # 10+20+15+5

def test_report_factory(sample_log_data):
    report = ReportFactory.create_report("handlers", sample_log_data)
    assert "HANDLER" in report

def test_report_factory_invalid_type(sample_log_data):
    with pytest.raises(ValueError):
        ReportFactory.create_report("invalid", sample_log_data)

def test_merge_stats():
    stats1 = {"/handler1": {"DEBUG": 1, "INFO": 2}}
    stats2 = {"/handler1": {"DEBUG": 3, "WARNING": 4}}
    merged = LogAnalyzer.merge_stats([stats1, stats2])
    assert merged["/handler1"]["DEBUG"] == 4
    assert merged["/handler1"]["INFO"] == 2
    assert merged["/handler1"]["WARNING"] == 4