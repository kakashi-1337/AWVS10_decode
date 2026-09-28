import json
import time
from typing import Optional


class Finding:
    def __init__(
        self,
        vuln_type: str,
        severity: str,
        url: str,
        parameter: str = "",
        payload: str = "",
        evidence: str = "",
        details: str = "",
        method: str = "GET",
    ):
        self.vuln_type = vuln_type
        self.severity = severity
        self.url = url
        self.parameter = parameter
        self.payload = payload
        self.evidence = evidence
        self.details = details
        self.method = method
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self):
        return {
            "type": self.vuln_type,
            "severity": self.severity,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "details": self.details,
            "method": self.method,
            "timestamp": self.timestamp,
        }

    def __str__(self):
        sev_colors = {
            "CRITICAL": "\033[91m",
            "HIGH": "\033[91m",
            "MEDIUM": "\033[93m",
            "LOW": "\033[94m",
            "INFO": "\033[90m",
        }
        reset = "\033[0m"
        color = sev_colors.get(self.severity, "")
        lines = [
            f"\n{color}[{self.severity}]{reset} {self.vuln_type}",
            f"  URL: {self.url}",
        ]
        if self.parameter:
            lines.append(f"  Parameter: {self.parameter}")
        if self.payload:
            lines.append(f"  Payload: {self.payload}")
        if self.evidence:
            lines.append(f"  Evidence: {self.evidence[:200]}")
        if self.details:
            lines.append(f"  Details: {self.details}")
        return "\n".join(lines)


class Reporter:
    def __init__(self, output_file: Optional[str] = None):
        self.findings: list[Finding] = []
        self.output_file = output_file
        self.start_time = time.time()

    def add(self, finding: Finding):
        self.findings.append(finding)
        print(finding)

    def summary(self, request_count: int = 0):
        elapsed = time.time() - self.start_time
        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)
        print(f"Duration: {elapsed:.1f}s")
        print(f"Requests: {request_count}")
        print(f"Findings: {len(self.findings)}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in counts:
                print(f"  {sev}: {counts[sev]}")
        print("=" * 60)

        if self.output_file:
            data = {
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration_seconds": round(elapsed, 1),
                "total_requests": request_count,
                "findings": [f.to_dict() for f in self.findings],
            }
            with open(self.output_file, "w") as fh:
                json.dump(data, fh, indent=2)
            print(f"\nResults saved to: {self.output_file}")
