from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin
from .models import UserProfile, UserWebsiteAccess


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'


class CustomUserAdmin(UserAdmin):
    inlines = (UserProfileInline,)


# Unregister the original User admin and register the custom one
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)


@admin.register(UserWebsiteAccess)
class UserWebsiteAccessAdmin(admin.ModelAdmin):
    list_display = ['user', 'website', 'role', 'granted_at']
    list_filter = ['role', 'granted_at', 'website']
    search_fields = ['user__username', 'user__email', 'website__name']
    readonly_fields = ['granted_at']
