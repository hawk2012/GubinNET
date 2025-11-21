# GubinNet - Django-based Website Constructor

GubinNet is a Django-based website constructor system similar to uCoz, designed to allow users to create and manage multiple websites with customizable templates and modular components.

## Features

- **Multi-site management**: Create and manage multiple websites from a single interface
- **Template system**: Support for custom templates with preview capabilities
- **Modular components**: Add different modules to websites (shop, blog, gallery, etc.)
- **SEO tools**: Built-in SEO optimization features
- **User management**: Role-based user management for each site
- **Shop module**: Integrated e-commerce functionality
- **Page management**: Create and edit pages with rich text editor

## Core Components

### GubinNet Module (Core)
The `gubinnet` module is the core of the system and provides all essential functionality:
- Site and page management
- Template system
- Component architecture
- SEO settings
- User management
- Shop module

This module can work independently and allows the website constructor to function autonomously. The `gubinnet` and related files can be removed from the repository when needed.

### Multi-site Constructor
The main application that uses GubinNet as its core to provide a complete website construction platform.

## Installation

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run migrations: `python manage.py migrate`
4. Create a superuser: `python manage.py createsuperuser`
5. Initialize default components and templates: `python manage.py initialize_constructor`
6. Start the development server: `python manage.py runserver`

## Usage

1. Access the admin panel at `/admin/` to manage sites, templates, and components
2. Create a new site through the admin panel
3. Add pages, customize templates, and install components
4. Configure SEO settings and user management per site

## Architecture

- **Sites**: Main entities representing individual websites
- **Templates**: Reusable design templates that can be applied to sites
- **Components**: Modular functionality that can be added to sites (shop, blog, etc.)
- **Pages**: Individual pages within each site
- **SEO Settings**: Search engine optimization configuration
- **User Management**: Registration, authentication and user role management
- **Shop Module**: E-commerce functionality with products and inventory

## Management Commands

- `initialize_constructor`: Creates default templates and components

## Admin Access

- URL: `/admin/`
- Default credentials: admin / admin123 (change after first login)

## Development

The system is designed to be extensible. You can add new components, templates, and features by extending the core models and views.
