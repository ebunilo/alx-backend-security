from django.core.management.base import BaseCommand
from ip_tracking.models import SuspiciousIP

class Command(BaseCommand):
    help = 'View all flagged suspicious IPs'

    def add_arguments(self, parser):
        parser.add_argument(
            '--active-only',
            action='store_true',
            help='Show only active suspicious IPs',
        )

    def handle(self, *args, **options):
        query = SuspiciousIP.objects.all()
        
        if options['active_only']:
            query = query.filter(is_active=True)
        
        if not query.exists():
            self.stdout.write(self.style.WARNING('No suspicious IPs found'))
            return
        
        self.stdout.write(self.style.SUCCESS('Suspicious IPs:'))
        for suspicious_ip in query:
            status = 'ACTIVE' if suspicious_ip.is_active else 'INACTIVE'
            self.stdout.write(
                f"  {suspicious_ip.ip_address} - {suspicious_ip.get_reason_display()} "
                f"({suspicious_ip.request_count} requests) [{status}]"
            )
