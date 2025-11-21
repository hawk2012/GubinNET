from django.contrib import admin
from .models import Website, Page


@admin.register(Website)
class WebsiteAdmin(admin.ModelAdmin):
    list_display = ['name', 'domain', 'subdomain', 'owner', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at', 'updated_at']
    search_fields = ['name', 'domain', 'subdomain']
    list_editable = ['is_active']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(Page)
class PageAdmin(admin.ModelAdmin):
    list_display = ['title', 'website', 'slug', 'is_published', 'created_at']
    list_filter = ['is_published', 'created_at', 'updated_at', 'website']
    search_fields = ['title', 'slug', 'content']
    list_editable = ['is_published']
    readonly_fields = ['created_at', 'updated_at']
