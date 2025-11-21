#!/usr/bin/env python
"""
Demo script to showcase the GubinNet website constructor functionality
"""
import os
import sys
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'multisite_constructor.settings')
django.setup()

from django.contrib.auth.models import User
from gubinnet.models import Site, Template, Component, Page, SeoSettings, UserManagement, ShopModule, Product

def demo():
    print("=== GubinNet Website Constructor Demo ===\n")
    
    # Show available templates
    print("1. Available Templates:")
    templates = Template.objects.filter(is_active=True)
    for template in templates:
        print(f"   - {template.name}: {template.description}")
    print()
    
    # Show available components
    print("2. Available Components:")
    components = Component.objects.filter(is_active=True)
    for component in components:
        print(f"   - {component.name} ({component.get_component_type_display()}): {component.description}")
    print()
    
    # Create a demo site
    print("3. Creating a demo site...")
    admin_user = User.objects.filter(is_superuser=True).first()
    if not admin_user:
        print("   Creating admin user...")
        admin_user = User.objects.create_superuser('admin', 'admin@example.com', 'admin123')
    
    demo_template = Template.objects.first()
    demo_site, created = Site.objects.get_or_create(
        name="Demo Site",
        domain="demo.example.com",
        owner=admin_user,
        defaults={'template': demo_template.name if demo_template else 'default'}
    )
    print(f"   Site created: {demo_site.name} ({demo_site.domain})")
    
    # Create a demo page
    print("4. Creating a demo page...")
    demo_page, created = Page.objects.get_or_create(
        site=demo_site,
        title="Главная страница",
        slug="home",
        defaults={
            'content': '<h1>Добро пожаловать на наш сайт!</h1><p>Это демонстрационная страница.</p>',
            'is_published': True
        }
    )
    print(f"   Page created: {demo_page.title}")
    
    # Show SEO settings
    print("5. SEO Settings for the site:")
    seo_settings, created = SeoSettings.objects.get_or_create(site=demo_site)
    print(f"   Meta title: {seo_settings.meta_title or 'Not set'}")
    print(f"   Meta description: {seo_settings.meta_description or 'Not set'}")
    
    # Show user management settings
    print("6. User Management Settings:")
    user_mgmt, created = UserManagement.objects.get_or_create(site=demo_site)
    print(f"   Registration allowed: {user_mgmt.allow_registration}")
    print(f"   Email verification required: {user_mgmt.require_email_verification}")
    
    # Show shop module
    print("7. Shop Module:")
    shop_module, created = ShopModule.objects.get_or_create(site=demo_site)
    print(f"   Currency: {shop_module.currency}")
    print(f   Shipping enabled: {shop_module.shipping_enabled}")
    
    # Create a demo product if shop exists
    if shop_module:
        demo_product, created = Product.objects.get_or_create(
            shop=shop_module,
            name="Demo Product",
            slug="demo-product",
            defaults={
                'description': '<p>This is a demo product</p>',
                'price': 99.99,
                'stock': 10,
                'is_active': True
            }
        )
        print(f"   Product created: {demo_product.name}")
    
    print("\n=== Demo completed successfully! ===")
    print("\nTo run the server, use: python manage.py runserver")
    print("Admin panel: http://127.0.0.1:8000/admin/ (admin / admin123)")

if __name__ == '__main__':
    demo()