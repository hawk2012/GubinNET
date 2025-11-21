from django.contrib import admin
from .models import Site, Page, Template, Component, SiteComponent, SeoSettings, UserManagement, ShopModule, Product


@admin.register(Site)
class SiteAdmin(admin.ModelAdmin):
    list_display = ['name', 'domain', 'owner', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'domain', 'owner__username']
    list_editable = ['is_active']


@admin.register(Page)
class PageAdmin(admin.ModelAdmin):
    list_display = ['title', 'site', 'is_published', 'created_at']
    list_filter = ['is_published', 'created_at', 'site']
    search_fields = ['title', 'site__name']
    list_editable = ['is_published']


@admin.register(Template)
class TemplateAdmin(admin.ModelAdmin):
    list_display = ['name', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'path']
    list_editable = ['is_active']


@admin.register(Component)
class ComponentAdmin(admin.ModelAdmin):
    list_display = ['name', 'component_type', 'is_active', 'created_at']
    list_filter = ['component_type', 'is_active', 'created_at']
    search_fields = ['name']
    list_editable = ['is_active']


@admin.register(SiteComponent)
class SiteComponentAdmin(admin.ModelAdmin):
    list_display = ['site', 'component', 'is_enabled', 'created_at']
    list_filter = ['is_enabled', 'created_at', 'component']
    search_fields = ['site__name', 'component__name']


@admin.register(SeoSettings)
class SeoSettingsAdmin(admin.ModelAdmin):
    list_display = ['site', 'meta_title']
    search_fields = ['site__name', 'meta_title']


@admin.register(UserManagement)
class UserManagementAdmin(admin.ModelAdmin):
    list_display = ['site', 'allow_registration']
    list_filter = ['allow_registration']
    search_fields = ['site__name']


@admin.register(ShopModule)
class ShopModuleAdmin(admin.ModelAdmin):
    list_display = ['site', 'currency', 'tax_rate']
    list_filter = ['currency']
    search_fields = ['site__name']


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ['name', 'shop', 'price', 'stock', 'is_active']
    list_filter = ['is_active', 'shop', 'created_at']
    search_fields = ['name', 'shop__site__name']
    list_editable = ['is_active', 'price', 'stock']