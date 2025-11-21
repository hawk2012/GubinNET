from django.contrib import admin
from .models import Component, WebsiteComponent


@admin.register(Component)
class ComponentAdmin(admin.ModelAdmin):
    list_display = ['name', 'component_type', 'is_active', 'created_at']
    list_filter = ['component_type', 'is_active', 'created_at', 'updated_at']
    search_fields = ['name', 'description']
    list_editable = ['is_active']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(WebsiteComponent)
class WebsiteComponentAdmin(admin.ModelAdmin):
    list_display = ['website', 'component', 'is_enabled', 'position', 'created_at']
    list_filter = ['is_enabled', 'position', 'created_at', 'updated_at', 'component__component_type']
    search_fields = ['website__name', 'component__name']
    list_editable = ['is_enabled', 'position']
    readonly_fields = ['created_at', 'updated_at']
