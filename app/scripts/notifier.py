import smtplib
import os
import json
from email.message import EmailMessage

class NotificationManager:
    def __init__(self):
        self.smtp_server = os.getenv("SMTP_SERVER")
        self.smtp_port = int(os.getenv("SMTP_PORT", 587))
        self.sender = os.getenv("ALERT_SENDER", "security-gate@company.com")
        self.recipient = os.getenv("AUDIT_MAILBOX", "security-audit@company.com")
        self.enabled = os.getenv("MAIL_ENABLED", "false").lower() == "true"

    def send_violation_report(self, repo_name, user, violation_data):
        """Sends a STARTTLS secured alert for High/Critical violations."""
        if not self.enabled:
            print("Logging violation (Email Disabled):", violation_data)
            return

        msg = EmailMessage()
        msg.set_content(f"""
        🚨 SECURITY POLICY VIOLATION DETECTED
        ------------------------------------
        Repository: {repo_name}
        User:       {user}
        Severity:   {violation_data.get('severity')}
        Reason:     {violation_data.get('reason')}
        
        Action Taken: Push Rejected / Image Quarantined.
        Reference: NIST SP 800-53 / DISA STIG
        """)

        msg['Subject'] = f"Security Alert: {repo_name} - {violation_data.get('severity')}"
        msg['From'] = self.sender
        msg['To'] = self.recipient

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls() # NIST SC-8 Compliance
                # server.login(user, pass) # Uncomment if relay requires auth
                server.send_message(msg)
        except Exception as e:
            print(f"Failed to send security alert: {str(e)}")

# Usage example for registry scanner integration:
# nm = NotificationManager()
# nm.send_violation_report("prod-app", "jdoe", {"severity": "Critical", "reason": "CVE-2026-1111"})