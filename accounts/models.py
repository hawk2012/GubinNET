from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    company_name = models.CharField(max_length=200, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    city = models.CharField(max_length=100, blank=True)
    country = models.CharField(max_length=100, blank=True)
    is_premium = models.BooleanField(default=False)
    max_sites = models.IntegerField(default=5)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.user.username}'s Profile"


class UserWebsiteAccess(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='website_access')
    website = models.ForeignKey('websites.Website', on_delete=models.CASCADE, related_name='user_access')
    role = models.CharField(max_length=20, choices=[
        ('owner', 'Owner'),
        ('admin', 'Admin'),
        ('editor', 'Editor'),
        ('viewer', 'Viewer')
    ], default='viewer')
    granted_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('user', 'website')
    
    def __str__(self):
        return f"{self.user.username} - {self.website.name} ({self.role})"
