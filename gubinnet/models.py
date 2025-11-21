from django.db import models
from django.contrib.auth.models import User
from ckeditor.fields import RichTextField
import os


class Site(models.Model):
    """
    Represents a website created by a user
    """
    name = models.CharField(max_length=200, verbose_name="Название сайта")
    domain = models.CharField(max_length=200, unique=True, verbose_name="Домен сайта")
    owner = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="Владелец сайта")
    template = models.CharField(max_length=200, default='default', verbose_name="Шаблон сайта")
    is_active = models.BooleanField(default=True, verbose_name="Активен")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Дата создания")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Дата обновления")
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = "Сайт"
        verbose_name_plural = "Сайты"


class Page(models.Model):
    """
    Represents a page within a website
    """
    site = models.ForeignKey(Site, on_delete=models.CASCADE, verbose_name="Сайт")
    title = models.CharField(max_length=200, verbose_name="Заголовок страницы")
    slug = models.SlugField(max_length=200, verbose_name="URL-адрес")
    content = RichTextField(verbose_name="Содержимое страницы")
    is_published = models.BooleanField(default=True, verbose_name="Опубликовано")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Дата создания")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Дата обновления")
    
    def __str__(self):
        return f"{self.site.name} - {self.title}"
    
    class Meta:
        verbose_name = "Страница"
        verbose_name_plural = "Страницы"


class Template(models.Model):
    """
    Represents a template that can be applied to a site
    """
    name = models.CharField(max_length=200, verbose_name="Название шаблона")
    path = models.CharField(max_length=500, verbose_name="Путь к шаблону")
    description = models.TextField(blank=True, verbose_name="Описание шаблона")
    preview_image = models.ImageField(upload_to='templates/previews/', blank=True, null=True, verbose_name="Превью шаблона")
    is_active = models.BooleanField(default=True, verbose_name="Активен")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Дата создания")
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = "Шаблон"
        verbose_name_plural = "Шаблоны"


class Component(models.Model):
    """
    Represents a modular component that can be added to sites
    """
    COMPONENT_TYPES = [
        ('shop', 'Магазин'),
        ('blog', 'Блог'),
        ('gallery', 'Галерея'),
        ('contact', 'Контакты'),
        ('seo', 'SEO инструменты'),
        ('users', 'Управление пользователями'),
        ('other', 'Другое'),
    ]
    
    name = models.CharField(max_length=200, verbose_name="Название компонента")
    component_type = models.CharField(max_length=50, choices=COMPONENT_TYPES, verbose_name="Тип компонента")
    description = models.TextField(blank=True, verbose_name="Описание компонента")
    is_active = models.BooleanField(default=True, verbose_name="Активен")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Дата создания")
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = "Компонент"
        verbose_name_plural = "Компоненты"


class SiteComponent(models.Model):
    """
    Represents a component added to a specific site
    """
    site = models.ForeignKey(Site, on_delete=models.CASCADE, verbose_name="Сайт")
    component = models.ForeignKey(Component, on_delete=models.CASCADE, verbose_name="Компонент")
    config = models.JSONField(default=dict, verbose_name="Конфигурация компонента")
    is_enabled = models.BooleanField(default=True, verbose_name="Включен")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Дата добавления")
    
    def __str__(self):
        return f"{self.site.name} - {self.component.name}"
    
    class Meta:
        verbose_name = "Компонент сайта"
        verbose_name_plural = "Компоненты сайта"


class SeoSettings(models.Model):
    """
    SEO settings for a site
    """
    site = models.OneToOneField(Site, on_delete=models.CASCADE, verbose_name="Сайт")
    meta_title = models.CharField(max_length=200, blank=True, verbose_name="Заголовок (meta title)")
    meta_description = models.TextField(max_length=500, blank=True, verbose_name="Описание (meta description)")
    meta_keywords = models.CharField(max_length=500, blank=True, verbose_name="Ключевые слова (meta keywords)")
    google_analytics = models.CharField(max_length=100, blank=True, verbose_name="Google Analytics ID")
    yandex_metrika = models.CharField(max_length=100, blank=True, verbose_name="Yandex Metrika ID")
    robots_txt = models.TextField(default="User-agent: *\nAllow: /", verbose_name="robots.txt")
    sitemap = models.TextField(blank=True, verbose_name="Карта сайта")
    
    def __str__(self):
        return f"SEO для {self.site.name}"
    
    class Meta:
        verbose_name = "SEO настройки"
        verbose_name_plural = "SEO настройки"


class UserManagement(models.Model):
    """
    User management settings for a site
    """
    site = models.OneToOneField(Site, on_delete=models.CASCADE, verbose_name="Сайт")
    allow_registration = models.BooleanField(default=True, verbose_name="Разрешить регистрацию")
    require_email_verification = models.BooleanField(default=True, verbose_name="Требовать подтверждение email")
    user_roles = models.JSONField(default=dict, verbose_name="Роли пользователей")
    registration_fields = models.JSONField(default=list, verbose_name="Дополнительные поля регистрации")
    
    def __str__(self):
        return f"Управление пользователями для {self.site.name}"
    
    class Meta:
        verbose_name = "Управление пользователями"
        verbose_name_plural = "Управление пользователями"


class ShopModule(models.Model):
    """
    Shop module for a site
    """
    site = models.OneToOneField(Site, on_delete=models.CASCADE, verbose_name="Сайт")
    currency = models.CharField(max_length=10, default='RUB', verbose_name="Валюта")
    tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0.00, verbose_name="Ставка налога (%)")
    shipping_enabled = models.BooleanField(default=True, verbose_name="Включить доставку")
    payment_methods = models.JSONField(default=list, verbose_name="Способы оплаты")
    inventory_tracking = models.BooleanField(default=True, verbose_name="Отслеживание остатков")
    
    def __str__(self):
        return f"Магазин для {self.site.name}"
    
    class Meta:
        verbose_name = "Модуль магазина"
        verbose_name_plural = "Модули магазина"


class Product(models.Model):
    """
    Product for the shop module
    """
    shop = models.ForeignKey(ShopModule, on_delete=models.CASCADE, verbose_name="Магазин")
    name = models.CharField(max_length=200, verbose_name="Название товара")
    slug = models.SlugField(max_length=200, verbose_name="URL-адрес")
    description = RichTextField(verbose_name="Описание товара")
    price = models.DecimalField(max_digits=10, decimal_places=2, verbose_name="Цена")
    stock = models.IntegerField(default=0, verbose_name="Количество на складе")
    is_active = models.BooleanField(default=True, verbose_name="Активен")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Дата создания")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Дата обновления")
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = "Товар"
        verbose_name_plural = "Товары"