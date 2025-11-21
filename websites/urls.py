from django.urls import path
from . import views

app_name = 'websites'

urlpatterns = [
    path('', views.website_list, name='website_list'),
    path('create/', views.website_create, name='website_create'),
    path('<int:pk>/', views.website_detail, name='website_detail'),
    path('<int:pk>/edit/', views.website_edit, name='website_edit'),
    path('<int:pk>/delete/', views.website_delete, name='website_delete'),
    path('<int:website_id>/pages/', views.page_list, name='page_list'),
    path('<int:website_id>/pages/create/', views.page_create, name='page_create'),
    path('pages/<int:pk>/', views.page_detail, name='page_detail'),
    path('pages/<int:pk>/edit/', views.page_edit, name='page_edit'),
    path('pages/<int:pk>/delete/', views.page_delete, name='page_delete'),
]