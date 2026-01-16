from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count
from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ['/admin', '/login', '/api/auth', '/api/users']
HIGH_REQUEST_THRESHOLD = 100  # Requests per hour
FAILED_LOGIN_THRESHOLD = 5  # Failed login attempts


@shared_task
def detect_anomalies():
    """
    Detect anomalous IP addresses based on:
    1. Request rate exceeding 100 requests/hour
    2. Access to sensitive paths
    3. Multiple failed login attempts
    """
    one_hour_ago = timezone.now() - timedelta(hours=1)
    
    # Get IPs with high request rates
    high_rate_ips = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(request_count=Count('id'))
        .filter(request_count__gt=HIGH_REQUEST_THRESHOLD)
    )
    
    for ip_data in high_rate_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        suspicious, created = SuspiciousIP.objects.get_or_create(
            ip_address=ip_address,
            defaults={
                'reason': 'high_request_rate',
                'request_count': request_count,
                'is_active': True,
            }
        )
        
        if not created:
            suspicious.request_count = request_count
            suspicious.reason = 'high_request_rate'
            suspicious.is_active = True
            suspicious.save()
    
    # Get IPs accessing sensitive paths
    sensitive_ips = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago, path__in=SENSITIVE_PATHS)
        .values('ip_address')
        .annotate(request_count=Count('id'))
        .filter(request_count__gt=FAILED_LOGIN_THRESHOLD)
    )
    
    for ip_data in sensitive_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        suspicious, created = SuspiciousIP.objects.get_or_create(
            ip_address=ip_address,
            defaults={
                'reason': 'sensitive_path_access',
                'request_count': request_count,
                'is_active': True,
            }
        )
        
        if not created and suspicious.reason != 'high_request_rate':
            suspicious.reason = 'sensitive_path_access'
            suspicious.request_count = request_count
            suspicious.is_active = True
            suspicious.save()
    
    # Deactivate suspicious IPs with no recent activity
    inactive_threshold = timezone.now() - timedelta(hours=24)
    SuspiciousIP.objects.filter(
        updated_at__lt=inactive_threshold,
        is_active=True
    ).update(is_active=False)
    
    return {
        'high_rate_ips_flagged': high_rate_ips.count(),
        'sensitive_path_ips_flagged': sensitive_ips.count(),
        'timestamp': str(timezone.now())
    }


@shared_task
def cleanup_old_logs():
    """
    Clean up old request logs older than 30 days to manage database size.
    """
    thirty_days_ago = timezone.now() - timedelta(days=30)
    deleted_count, _ = RequestLog.objects.filter(
        timestamp__lt=thirty_days_ago
    ).delete()
    
    return {'logs_deleted': deleted_count, 'timestamp': str(timezone.now())}