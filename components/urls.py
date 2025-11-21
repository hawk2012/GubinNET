from django.urls import path
from . import views

app_name = 'components'

urlpatterns = [
    path('', views.component_list, name='component_list'),
    path('create/', views.component_create, name='component_create'),
    path('<int:pk>/', views.component_detail, name='component_detail'),
    path('<int:pk>/edit/', views.component_edit, name='component_edit'),
    path('<int:pk>/delete/', views.component_delete, name='component_delete'),
    path('website/<int:website_id>/', views.website_component_list, name='website_component_list'),
    path('website/<int:website_id>/add/', views.website_component_add, name='website_component_add'),
    path('website/<int:website_id>/component/<int:pk>/edit/', views.website_component_edit, name='website_component_edit'),
    path('website/<int:website_id>/component/<int:pk>/delete/', views.website_component_delete, name='website_component_delete'),
]