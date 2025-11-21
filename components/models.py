from django.db import models
from websites.models import Website


class Component(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    component_type = models.CharField(max_length=50, choices=[
        ('shop', 'Shop/E-commerce'),
        ('blog', 'Blog'),
        ('gallery', 'Gallery'),
        ('contact', 'Contact Form'),
        ('social', 'Social Media'),
        ('analytics', 'Analytics'),
        ('other', 'Other')
    ])
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name


class WebsiteComponent(models.Model):
    website = models.ForeignKey(Website, on_delete=models.CASCADE, related_name='website_components')
    component = models.ForeignKey(Component, on_delete=models.CASCADE)
    configuration = models.JSONField(default=dict, blank=True)
    is_enabled = models.BooleanField(default=True)
    position = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['position']
    
    def __str__(self):
        return f"{self.website.name} - {self.component.name}"
