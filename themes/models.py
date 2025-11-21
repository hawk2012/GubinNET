from django.db import models


class Theme(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    version = models.CharField(max_length=20)
    author = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    is_premium = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name


class ThemeFile(models.Model):
    theme = models.ForeignKey(Theme, on_delete=models.CASCADE, related_name='files')
    file_path = models.CharField(max_length=500)
    file_type = models.CharField(max_length=50, choices=[
        ('html', 'HTML Template'),
        ('css', 'CSS File'),
        ('js', 'JavaScript File'),
        ('img', 'Image'),
        ('other', 'Other')
    ])
    content = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.theme.name} - {self.file_path}"
