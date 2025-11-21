from django.urls import path
from . import views

app_name = 'gubinnet'

urlpatterns = [
    # Main site constructor views
    path('', views.home, name='home'),
    path('sites/', views.site_list, name='site_list'),
    path('sites/create/', views.site_create, name='site_create'),
    path('sites/<int:site_id>/', views.site_detail, name='site_detail'),
    path('sites/<int:site_id>/edit/', views.site_edit, name='site_edit'),
    
    # Page management
    path('sites/<int:site_id>/pages/', views.page_list, name='page_list'),
    path('sites/<int:site_id>/pages/create/', views.page_create, name='page_create'),
    path('sites/<int:site_id>/pages/<int:page_id>/edit/', views.page_edit, name='page_edit'),
    
    # Template management
    path('templates/', views.template_list, name='template_list'),
    path('templates/<int:template_id>/', views.template_detail, name='template_detail'),
    
    # Component management
    path('components/', views.component_list, name='component_list'),
    path('components/<int:component_id>/add/', views.component_add, name='component_add'),
    
    # SEO management
    path('sites/<int:site_id>/seo/', views.seo_edit, name='seo_edit'),
    
    # User management
    path('sites/<int:site_id>/users/', views.user_management, name='user_management'),
    
    # Shop management
    path('sites/<int:site_id>/shop/', views.shop_module, name='shop_module'),
    path('sites/<int:site_id>/shop/products/', views.product_list, name='product_list'),
    path('sites/<int:site_id>/shop/products/create/', views.product_create, name='product_create'),
]