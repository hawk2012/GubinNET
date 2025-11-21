from django.contrib import admin
from .models import SEOMetadata, SEORank


@admin.register(SEOMetadata)
class SEOMetadataAdmin(admin.ModelAdmin):
    list_display = ['website', 'get_page_title', 'title', 'updated_at']
    list_filter = ['created_at', 'updated_at', 'website']
    search_fields = ['title', 'description', 'keywords', 'website__name', 'page__title']
    readonly_fields = ['created_at', 'updated_at']
    
    def get_page_title(self, obj):
        return obj.page.title if obj.page else "Website SEO"
    get_page_title.short_description = 'Page Title'


@admin.register(SEORank)
class SEORankAdmin(admin.ModelAdmin):
    list_display = ['website', 'keyword', 'rank', 'search_engine', 'checked_at']
    list_filter = ['search_engine', 'checked_at', 'website']
    search_fields = ['keyword', 'website__name']
    readonly_fields = ['checked_at']
