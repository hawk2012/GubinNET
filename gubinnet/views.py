from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Site, Page, Template, Component, SiteComponent, SeoSettings, UserManagement, ShopModule, Product


def home(request):
    """Main page of the website constructor"""
    sites = Site.objects.filter(owner=request.user) if request.user.is_authenticated else Site.objects.none()
    context = {
        'sites': sites,
        'templates': Template.objects.filter(is_active=True)[:6],
        'components': Component.objects.filter(is_active=True)[:6],
    }
    return render(request, 'gubinnet/home.html', context)


@login_required
def site_list(request):
    """List all sites for the current user"""
    sites = Site.objects.filter(owner=request.user)
    context = {
        'sites': sites
    }
    return render(request, 'gubinnet/site_list.html', context)


@login_required
def site_create(request):
    """Create a new site"""
    if request.method == 'POST':
        name = request.POST.get('name')
        domain = request.POST.get('domain')
        template = request.POST.get('template', 'default')
        
        # Validate domain uniqueness
        if Site.objects.filter(domain=domain).exists():
            messages.error(request, 'Домен уже используется')
            return redirect('gubinnet:site_create')
        
        site = Site.objects.create(
            name=name,
            domain=domain,
            owner=request.user,
            template=template
        )
        
        # Create default SEO settings
        SeoSettings.objects.create(site=site)
        
        # Create default User Management settings
        UserManagement.objects.create(site=site)
        
        # Create default Shop module
        ShopModule.objects.create(site=site)
        
        messages.success(request, 'Сайт успешно создан')
        return redirect('gubinnet:site_detail', site_id=site.id)
    
    templates = Template.objects.filter(is_active=True)
    context = {
        'templates': templates
    }
    return render(request, 'gubinnet/site_create.html', context)


def site_detail(request, site_id):
    """Display site details"""
    site = get_object_or_404(Site, id=site_id)
    
    # Check if user has permission to view this site
    if site.owner != request.user and not request.user.is_superuser:
        messages.error(request, 'У вас нет прав для просмотра этого сайта')
        return redirect('gubinnet:home')
    
    pages = Page.objects.filter(site=site, is_published=True)
    components = SiteComponent.objects.filter(site=site, is_enabled=True)
    
    context = {
        'site': site,
        'pages': pages,
        'components': components
    }
    return render(request, 'gubinnet/site_detail.html', context)


@login_required
def site_edit(request, site_id):
    """Edit site details"""
    site = get_object_or_404(Site, id=site_id, owner=request.user)
    
    if request.method == 'POST':
        site.name = request.POST.get('name')
        site.domain = request.POST.get('domain')
        site.template = request.POST.get('template')
        site.save()
        
        messages.success(request, 'Сайт успешно обновлен')
        return redirect('gubinnet:site_detail', site_id=site.id)
    
    templates = Template.objects.filter(is_active=True)
    context = {
        'site': site,
        'templates': templates
    }
    return render(request, 'gubinnet/site_edit.html', context)


@login_required
def page_list(request, site_id):
    """List pages for a specific site"""
    site = get_object_or_404(Site, id=site_id, owner=request.user)
    pages = Page.objects.filter(site=site)
    
    context = {
        'site': site,
        'pages': pages
    }
    return render(request, 'gubinnet/page_list.html', context)


@login_required
def page_create(request, site_id):
    """Create a new page for a site"""
    site = get_object_or_404(Site, id=site_id, owner=request.user)
    
    if request.method == 'POST':
        title = request.POST.get('title')
        slug = request.POST.get('slug')
        content = request.POST.get('content')
        is_published = request.POST.get('is_published') == 'on'
        
        Page.objects.create(
            site=site,
            title=title,
            slug=slug,
            content=content,
            is_published=is_published
        )
        
        messages.success(request, 'Страница успешно создана')
        return redirect('gubinnet:page_list', site_id=site.id)
    
    context = {
        'site': site
    }
    return render(request, 'gubinnet/page_create.html', context)


@login_required
def page_edit(request, site_id, page_id):
    """Edit a page for a site"""
    site = get_object_or_404(Site, id=site_id, owner=request.user)
    page = get_object_or_404(Page, id=page_id, site=site)
    
    if request.method == 'POST':
        page.title = request.POST.get('title')
        page.slug = request.POST.get('slug')
        page.content = request.POST.get('content')
        page.is_published = request.POST.get('is_published') == 'on'
        page.save()
        
        messages.success(request, 'Страница успешно обновлена')
        return redirect('gubinnet:page_list', site_id=site.id)
    
    context = {
        'site': site,
        'page': page
    }
    return render(request, 'gubinnet/page_edit.html', context)


def template_list(request):
    """List all available templates"""
    templates = Template.objects.filter(is_active=True)
    context = {
        'templates': templates
    }
    return render(request, 'gubinnet/template_list.html', context)


def template_detail(request, template_id):
    """Display template details"""
    template = get_object_or_404(Template, id=template_id)
    context = {
        'template': template
    }
    return render(request, 'gubinnet/template_detail.html', context)


@login_required
def component_list(request):
    """List all available components"""
    components = Component.objects.filter(is_active=True)
    context = {
        'components': components
    }
    return render(request, 'gubinnet/component_list.html', context)


@login_required
def component_add(request, component_id):
    """Add a component to a site"""
    component = get_object_or_404(Component, id=component_id, is_active=True)
    
    if request.method == 'POST':
        site_id = request.POST.get('site_id')
        site = get_object_or_404(Site, id=site_id, owner=request.user)
        
        # Check if component is already added to this site
        if SiteComponent.objects.filter(site=site, component=component).exists():
            messages.error(request, 'Компонент уже добавлен к этому сайту')
            return redirect('gubinnet:component_list')
        
        SiteComponent.objects.create(
            site=site,
            component=component
        )
        
        messages.success(request, f'Компонент "{component.name}" добавлен к сайту')
        return redirect('gubinnet:site_detail', site_id=site.id)
    
    sites = Site.objects.filter(owner=request.user)
    context = {
        'component': component,
        'sites': sites
    }
    return render(request, 'gubinnet/component_add.html', context)


@login_required
def seo_edit(request, site_id):
    """Edit SEO settings for a site"""
    site = get_object_or_404(Site, id=site_id, owner=request.user)
    seo_settings, created = SeoSettings.objects.get_or_create(site=site)
    
    if request.method == 'POST':
        seo_settings.meta_title = request.POST.get('meta_title')
        seo_settings.meta_description = request.POST.get('meta_description')
        seo_settings.meta_keywords = request.POST.get('meta_keywords')
        seo_settings.google_analytics = request.POST.get('google_analytics')
        seo_settings.yandex_metrika = request.POST.get('yandex_metrika')
        seo_settings.robots_txt = request.POST.get('robots_txt')
        seo_settings.sitemap = request.POST.get('sitemap')
        seo_settings.save()
        
        messages.success(request, 'SEO настройки успешно обновлены')
        return redirect('gubinnet:seo_edit', site_id=site.id)
    
    context = {
        'site': site,
        'seo_settings': seo_settings
    }
    return render(request, 'gubinnet/seo_edit.html', context)


@login_required
def user_management(request, site_id):
    """Manage user settings for a site"""
    site = get_object_or_404(Site, id=site_id, owner=request.user)
    user_management, created = UserManagement.objects.get_or_create(site=site)
    
    if request.method == 'POST':
        user_management.allow_registration = request.POST.get('allow_registration') == 'on'
        user_management.require_email_verification = request.POST.get('require_email_verification') == 'on'
        user_management.user_roles = request.POST.get('user_roles', '{}')
        user_management.registration_fields = request.POST.get('registration_fields', '[]')
        user_management.save()
        
        messages.success(request, 'Настройки управления пользователями успешно обновлены')
        return redirect('gubinnet:user_management', site_id=site.id)
    
    context = {
        'site': site,
        'user_management': user_management
    }
    return render(request, 'gubinnet/user_management.html', context)


@login_required
def shop_module(request, site_id):
    """Manage shop module for a site"""
    site = get_object_or_404(Site, id=site_id, owner=request.user)
    shop_module, created = ShopModule.objects.get_or_create(site=site)
    
    if request.method == 'POST':
        shop_module.currency = request.POST.get('currency', 'RUB')
        shop_module.tax_rate = request.POST.get('tax_rate', 0)
        shop_module.shipping_enabled = request.POST.get('shipping_enabled') == 'on'
        shop_module.payment_methods = request.POST.get('payment_methods', '[]')
        shop_module.inventory_tracking = request.POST.get('inventory_tracking') == 'on'
        shop_module.save()
        
        messages.success(request, 'Настройки магазина успешно обновлены')
        return redirect('gubinnet:shop_module', site_id=site.id)
    
    products = Product.objects.filter(shop=shop_module)
    context = {
        'site': site,
        'shop_module': shop_module,
        'products': products
    }
    return render(request, 'gubinnet/shop_module.html', context)


@login_required
def product_list(request, site_id):
    """List products for a shop"""
    site = get_object_or_404(Site, id=site_id, owner=request.user)
    shop_module = get_object_or_404(ShopModule, site=site)
    products = Product.objects.filter(shop=shop_module)
    
    context = {
        'site': site,
        'shop_module': shop_module,
        'products': products
    }
    return render(request, 'gubinnet/product_list.html', context)


@login_required
def product_create(request, site_id):
    """Create a new product for a shop"""
    site = get_object_or_404(Site, id=site_id, owner=request.user)
    shop_module = get_object_or_404(ShopModule, site=site)
    
    if request.method == 'POST':
        name = request.POST.get('name')
        slug = request.POST.get('slug')
        description = request.POST.get('description')
        price = request.POST.get('price')
        stock = request.POST.get('stock', 0)
        is_active = request.POST.get('is_active') == 'on'
        
        Product.objects.create(
            shop=shop_module,
            name=name,
            slug=slug,
            description=description,
            price=price,
            stock=stock,
            is_active=is_active
        )
        
        messages.success(request, 'Товар успешно создан')
        return redirect('gubinnet:product_list', site_id=site.id)
    
    context = {
        'site': site,
        'shop_module': shop_module
    }
    return render(request, 'gubinnet/product_create.html', context)