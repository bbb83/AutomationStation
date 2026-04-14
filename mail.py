import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv

load_dotenv()

SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
MAIL_FROM = os.getenv("MAIL_FROM")
MAIL_TO = os.getenv("MAIL_TO")
SCORE_THRESHOLD = float(os.getenv("SCORE_THRESHOLD", 0.5))


def build_flagged_list(scored_results):
    flagged = []
 
    for device, result in scored_results:
        if result.overall_score < SCORE_THRESHOLD:
            failed_tests = [
                f"{t.name} ({t.category})"
                for t in result.tests
                if not t.passed
            ]
            flagged.append({
                "ip": device.ip,
                "hostname": device.get_hostname() or "unknown",
                "score": round(result.overall_score, 2),
                "failed_tests": failed_tests,
            })
 
    return flagged
 
 
def build_fail_html(flagged):
    rows = ""
 
    for device in flagged:
        failed = "<br>".join(device["failed_tests"]) if device["failed_tests"] else "none"
        rows += f"""
        <tr>
            <td>{device["ip"]}</td>
            <td>{device["hostname"]}</td>
            <td>{device["score"]}</td>
            <td>{failed}</td>
        </tr>
        """
 
    html = f"""
    <html>
    <body>
        <h2>Network Scan Alert</h2>
        <p>{len(flagged)} device(s) flagged with a score below {SCORE_THRESHOLD}:</p>
        <table border="1">
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Hostname</th>
                    <th>Score</th>
                    <th>Failed Tests</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        <p>Sent by network scanner - review flagged devices in NetBox.</p>
    </body>
    </html>
    """
 
    return html
 
def build_success_html(scored_results):
    rows = ""
    for device, result in scored_results:
        rows += f"""
        <tr>
            <td>{device.ip}</td>
            <td>{device.get_hostname() or "unknown"}</td>
            <td>{round(result.overall_score, 2)}</td>
        </tr>
        """

    html = f"""
    <html>
    <body>
        <h2>Network Scan Alert</h2>
        <p>All devices added were at or above the score threshold {SCORE_THRESHOLD}.</p>
        <table border="1">
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Hostname</th>
                    <th>Score</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        <p>Sent by network scanner - review flagged devices in NetBox.</p>
    </body>
    </html>
    """
    return html

 
def send_issue_report(scored_results):
    flagged = build_flagged_list(scored_results)
 
    if not flagged:
        html = build_success_html(scored_results)
    else:
        html = build_fail_html(flagged)
 
    message = MIMEMultipart("alternative")
    message["From"] = MAIL_FROM
    message["To"] = MAIL_TO
    message["Subject"] = f"Network Scan Alert — {len(flagged)} device(s) flagged"
 
    message.attach(MIMEText(html, "html"))
 
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(MAIL_FROM, MAIL_TO, message.as_string())
        print(f"[mailer] Email sent — {len(flagged)} device(s) flagged.")
    except smtplib.SMTPAuthenticationError:
        print("[mailer] Authentication failed — check SMTP_USER and SMTP_PASS in .env")
    except smtplib.SMTPConnectError:
        print("[mailer] Could not connect to SMTP server — check SMTP_HOST and SMTP_PORT in .env")
    except Exception as e:
        print(f"[mailer] Failed to send email: {e}")

# Testing
# if __name__ == "__main__":
#     test_results = [
#         (
#             type("Device", (), {
#                 "ip": "192.168.1.10",
#                 "get_hostname": lambda self: "test-device-1",
#                 "evidence": [],
#             })(),
#             type("Result", (), {
#                 "overall_score": 0.5,
#                 "tests": [
#                     type("Test", (), {"name": "ping", "category": "existence", "passed": True})(),
#                     type("Test", (), {"name": "mac known", "category": "identity", "passed": True})(),
#                     type("Test", (), {"name": "port scan", "category": "classification", "passed": True})(),
#                 ],
#             })(),
#         ),
#         (
#             type("Device", (), {
#                 "ip": "192.168.1.20",
#                 "get_hostname": lambda self: None,
#                 "evidence": [],
#             })(),
#             type("Result", (), {
#                 "overall_score": 0.8,
#                 "tests": [
#                     type("Test", (), {"name": "ping", "category": "existence", "passed": True})(),
#                 ],
#             })(),
#         ),
#     ]

#     send_issue_report(test_results)