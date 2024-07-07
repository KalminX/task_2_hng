from django.contrib import admin
from .models import User, Organisation


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    # Include 'userId' in list_display
    list_display = ('id', 'username', 'email',
                    'userId', 'first_name', 'last_name')
    # Add fields for search functionality
    search_fields = ('username', 'email', 'first_name', 'last_name')

@admin.register(Organisation)
class OrganisationAdmin(admin.ModelAdmin):
    list_display = ('name', 'orgId')