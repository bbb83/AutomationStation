import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
from datetime import datetime
import time

MAX_RETRIES = 3
RETRY_DELAY = 2 # in seconds, doubles each attempt

# Loads env variables
load_dotenv()
SMTP_PORT = int(os.getenv("SMTP_PORT", 587)) # default of 587
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
MAIL_FROM = os.getenv("MAIL_FROM")
MAIL_TO = [addr.strip() for addr in os.getenv("MAIL_TO", "").split(",") if addr.strip()] # multiple receivers separated by a comma.
SCORE_THRESHOLD = float(os.getenv("MAIL_REPORT_THRESHOLD", 40)) # default of 40

# Builds a list of result entries that scored less than the SCORE_THRESHOLD
def build_flagged_list(scored_results):
    print("Building list of flagged results.")
    flagged = []

    print(f"Appending results with a score less than {SCORE_THRESHOLD} to list.")
    for device, result in scored_results:
        if result.overall_score < SCORE_THRESHOLD:
            # adds each entry
            flagged.append({
                "ip": device.ip,
                "hostname": device.get_hostname() or "unknown",
                "score": round(result.overall_score, 2),
            })
    print("Flagged list of IPs have been built.")
    return flagged

# html attachment for MIME
# builds html body with the flagged list (failed entries)
def build_fail_html(flagged):
    print("Formating email body.")
    rows = ""
    # builds table
    for device in flagged:
        rows += f"""
        <tr>
            <td>{device["ip"]}</td>
            <td>{device["hostname"]}</td>
            <td>{device["score"]}</td>
        </tr>
        """
    # html body
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
# builds html body with the regular scored_results list (successful entries)
def build_success_html(scored_results):
    print("Formating email body.")
    rows = ""
    # builds table
    for device, result in scored_results:
        rows += f"""
        <tr>
            <td>{device.ip}</td>
            <td>{device.get_hostname() or "unknown"}</td>
            <td>{round(result.overall_score, 2)}</td>
        </tr>
        """
    # builds html body
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

# plain text attachment for MIME
# builds plain text file for flagged list
def build_fail_text(flagged):
    lines = [f"Network Scan Alert - {len(flagged)} device(s) flagged below {SCORE_THRESHOLD}\n"]
    for device in flagged:
        lines.append(f"  {device['ip']} ({device['hostname']}) - score: {device['score']}")
    lines.append("Review flagged devices in NetBox.")
    return "\n".join(lines)
# builds plain text file for successful results list
def build_success_text(scored_results):
    lines = [f"Network Scan Alert - all devices at or above {SCORE_THRESHOLD}\n"]
    for device, result in scored_results:
        lines.append(f"  {device.ip} ({device.get_hostname() or 'unknown'}) - score: {round(result.overall_score, 2)}")
    lines.append("\nReview devices in NetBox.")
    return "\n".join(lines)

# rebuilds list to include, builds email, and attempts to send to recepients.
def send_issue_report(scored_results):
    # Choosing and building which table
    print("Preparing to send email containing low scoring results")

    flagged = build_flagged_list(scored_results)

    print("Building email:")
    if not flagged: # success
        print("Results have all passed Score Threshold, building success e-mail body.")
        html = build_success_html(scored_results)
        plain = build_success_text(scored_results)
    else: # failed
        print("Results contain a failed Score Threshold, building failure e-mail body.")
        html = build_fail_html(flagged)
        plain = build_fail_text(flagged)

    # Building MIME with MAIL_FROM, MAIL_TO and the attachments. has time recording
    print("Inserting mime information.")
    message = MIMEMultipart("alternative")
    message["From"] = MAIL_FROM
    message["To"] =  ", ".join(MAIL_TO)
    message["Subject"] = f"Network Scan Alert - {len(flagged)} device(s) flagged {datetime.now()}"
    message.attach(MIMEText(plain, "plain"))
    message.attach(MIMEText(html, "html"))

    # Attempts to send email multiple times with the delay between
    # attempts growing by attempt amount each time.
    # Ex. 2s initial delay x 2nd attempt = 4s delay
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            # Connects to smtp server and attempts to send email
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(MAIL_FROM, MAIL_TO, message.as_string())
            print(f"[mailer] Email sent — {len(flagged)} device(s) flagged.")
            return True
        # fails at user credential level.
        except smtplib.SMTPAuthenticationError:
            print("[mailer] Authentication failed — check SMTP_USER and SMTP_PASS in .env")
            return False
        # fails at smtp server level
        except smtplib.SMTPConnectError:
            print("[mailer] Could not connect to SMTP server — check SMTP_HOST and SMTP_PORT in .env")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)
        # fails elsewhere
        except Exception as e:
            print(f"[mailer] Failed to send email: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)
    # exceeded attempts
    print("[mail] All retry attempts have failed. E-mail was not sent.")
    return False

# # Singular file testing
# if __name__ == "__main__":
#     test_results = [
#         (
#             type("Device", (), {
#                 "ip": "192.168.1.10",
#                 "get_hostname": lambda self: "test-device-1",
#                 "evidence": [],
#             })(),
#             type("Result", (), {
#                 "overall_score": 30,
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
#                 "overall_score": 80,
#                 "tests": [
#                     type("Test", (), {"name": "ping", "category": "existence", "passed": True})(),
#                 ],
#             })(),
#         ),
#     ]
#     send_issue_report(test_results)
