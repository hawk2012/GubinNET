#!/usr/bin/env python
import os
import sys
from django.core.management import execute_from_command_line
from django.conf import settings
import django

def setup_project():
    # Set the Django settings module
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'multisite_constructor.settings')
    
    # Setup Django
    django.setup()
    
    # Run migrations
    print("Running migrations...")
    execute_from_command_line(['manage.py', 'makemigrations'])
    execute_from_command_line(['manage.py', 'migrate'])
    
    # Create a superuser
    from django.contrib.auth.models import User
    if not User.objects.filter(is_superuser=True).exists():
        print("Creating superuser...")
        User.objects.create_superuser('admin', 'admin@example.com', 'admin123')
        print("Superuser created: admin / admin123")
    
    # Initialize the constructor
    print("Initializing constructor with default components and templates...")
    execute_from_command_line(['manage.py', 'initialize_constructor'])
    
    print("Setup completed successfully!")
    print("You can now run the server with: python manage.py runserver")

if __name__ == '__main__':
    setup_project()