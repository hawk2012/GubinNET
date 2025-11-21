from django.urls import path
from . import views

app_name = 'themes'

urlpatterns = [
    path('', views.theme_list, name='theme_list'),
    path('create/', views.theme_create, name='theme_create'),
    path('<int:pk>/', views.theme_detail, name='theme_detail'),
    path('<int:pk>/edit/', views.theme_edit, name='theme_edit'),
    path('<int:pk>/delete/', views.theme_delete, name='theme_delete'),
    path('<int:theme_id>/files/', views.theme_file_list, name='theme_file_list'),
    path('<int:theme_id>/files/create/', views.theme_file_create, name='theme_file_create'),
    path('files/<int:pk>/', views.theme_file_detail, name='theme_file_detail'),
    path('files/<int:pk>/edit/', views.theme_file_edit, name='theme_file_edit'),
    path('files/<int:pk>/delete/', views.theme_file_delete, name='theme_file_delete'),
]