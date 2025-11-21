from django.db import models
from websites.models import Website, Page


class SEOMetadata(models.Model):
    website = models.ForeignKey(Website, on_delete=models.CASCADE, related_name='seo_metadata')
    page = models.ForeignKey(Page, on_delete=models.CASCADE, related_name='seo_metadata', null=True, blank=True)
    title = models.CharField(max_length=60, help_text="Recommended: 50-60 characters")
    description = models.CharField(max_length=160, help_text="Recommended: 150-160 characters")
    keywords = models.TextField(blank=True, help_text="Comma separated keywords")
    slug = models.SlugField(max_length=200, blank=True)
    og_title = models.CharField(max_length=100, blank=True)
    og_description = models.CharField(max_length=300, blank=True)
    og_image = models.URLField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('website', 'page')
    
    def __str__(self):
        if self.page:
            return f"SEO for {self.website.name} - {self.page.title}"
        return f"SEO for {self.website.name}"


class SEORank(models.Model):
    website = models.ForeignKey(Website, on_delete=models.CASCADE, related_name='seo_ranks')
    keyword = models.CharField(max_length=200)
    rank = models.IntegerField(help_text="Position in search results")
    search_engine = models.CharField(max_length=50, default='Google')
    checked_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.website.name} - {self.keyword} - #{self.rank}"
