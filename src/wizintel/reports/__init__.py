"""Report generation."""

from wizintel.reports.csv_report import write_csv_report
from wizintel.reports.html import write_html_report
from wizintel.reports.json_report import write_json_report

__all__ = ["write_csv_report", "write_html_report", "write_json_report"]
