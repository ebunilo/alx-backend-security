from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django_ip_geolocation.models import IPGeolocation
from .models import RequestLog, BlockedIP

class RequestLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)

        # Check if IP is blocked
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("IP address is blocked")

        # Log the request details with geolocation
        path = request.path
        country, city = self.get_geolocation(ip)
        RequestLog.objects.create(ip_address=ip, path=path, country=country, city=city)

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def get_geolocation(self, ip):
        """
        Fetch geolocation data for an IP address with 24-hour caching.
        Returns a tuple of (country, city).
        """
        cache_key = f"geolocation_{ip}"
        
        # Try to get from cache
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data
        
        try:
            # Fetch geolocation data
            geo_data = IPGeolocation.objects.filter(ip_address=ip).first()
            
            if geo_data:
                country = geo_data.country
                city = geo_data.city
            else:
                country = None
                city = None
            
            # Cache for 24 hours (86400 seconds)
            cache.set(cache_key, (country, city), 86400)
            return country, city
        except Exception as e:
            # Log error and return None values if geolocation fails
            print(f"Geolocation error for IP {ip}: {str(e)}")
            return None, None
