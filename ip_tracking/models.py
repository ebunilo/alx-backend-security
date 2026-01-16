from django.db import models

class RequestLog(models.Model):
    ip_address = models.CharField(max_length=45)  # IPv6 can be up to 45 chars
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=500)
    country = models.CharField(max_length=100, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return f"{self.ip_address} - {self.path} at {self.timestamp}"

class BlockedIP(models.Model):
    ip_address = models.CharField(max_length=45, unique=True)

    def __str__(self):
        return self.ip_address

class SuspiciousIP(models.Model):
    REASON_CHOICES = [
        ('high_request_rate', 'High Request Rate'),
        ('sensitive_path_access', 'Sensitive Path Access'),
        ('multiple_failed_logins', 'Multiple Failed Logins'),
        ('admin_access', 'Admin Panel Access'),
    ]
    
    ip_address = models.CharField(max_length=45, unique=True)
    reason = models.CharField(max_length=50, choices=REASON_CHOICES)
    request_count = models.IntegerField(default=0)
    flagged_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.ip_address} - {self.get_reason_display()}"

    class Meta:
        ordering = ['-flagged_at']
