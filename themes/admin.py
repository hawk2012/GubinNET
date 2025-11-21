from django.contrib import admin
from .models import Theme, ThemeFile


@admin.register(Theme)
class ThemeAdmin(admin.ModelAdmin):
    list_display = ['name', 'version', 'author', 'is_active', 'is_premium', 'created_at']
    list_filter = ['is_active', 'is_premium', 'created_at', 'updated_at']
    search_fields = ['name', 'author', 'description']
    list_editable = ['is_active', 'is_premium']
    readonly_fields = ['created_at', 'updated_at']


class ThemeFileInline(admin.TabularInline):
    model = ThemeFile
    extra = 1


@admin.register(ThemeFile)
class ThemeFileAdmin(admin.ModelAdmin):
    list_display = ['theme', 'file_path', 'file_type', 'created_at']
    list_filter = ['file_type', 'created_at', 'theme']
    search_fields = ['file_path', 'theme__name']
    readonly_fields = ['created_at']
