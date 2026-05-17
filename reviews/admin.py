from django.contrib import admin

from pam.admin_site import admin_site
from .models import AccessReview, ReviewEntry


class ReviewEntryInline(admin.TabularInline):
    model = ReviewEntry
    extra = 0
    readonly_fields = ('access_request', 'decision', 'reviewed_by', 'reviewed_at')


@admin_site.register(AccessReview)
class AccessReviewAdmin(admin.ModelAdmin):
    list_display = ('name', 'status', 'created_by', 'due_date', 'created_at')
    list_filter = ('status',)
    search_fields = ('name', 'description')
    filter_horizontal = ('reviewers',)
    inlines = [ReviewEntryInline]


@admin_site.register(ReviewEntry)
class ReviewEntryAdmin(admin.ModelAdmin):
    list_display = ('review', 'access_request', 'decision', 'reviewed_by', 'reviewed_at')
    list_filter = ('decision',)
