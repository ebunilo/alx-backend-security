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
