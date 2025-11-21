from django.core.management.base import BaseCommand
from gubinnet.models import Component, Template


class Command(BaseCommand):
    help = 'Initialize the website constructor with default components and templates'

    def handle(self, *args, **options):
        # Create default templates
        templates_data = [
            {'name': 'Business', 'path': 'templates/business/', 'description': 'Шаблон для бизнес-сайтов'},
            {'name': 'Portfolio', 'path': 'templates/portfolio/', 'description': 'Шаблон для портфолио'},
            {'name': 'Blog', 'path': 'templates/blog/', 'description': 'Шаблон для блога'},
            {'name': 'Shop', 'path': 'templates/shop/', 'description': 'Шаблон для интернет-магазина'},
            {'name': 'Landing', 'path': 'templates/landing/', 'description': 'Шаблон для лендинга'},
        ]
        
        for template_data in templates_data:
            template, created = Template.objects.get_or_create(
                name=template_data['name'],
                defaults={
                    'path': template_data['path'],
                    'description': template_data['description']
                }
            )
            if created:
                self.stdout.write(f'Создан шаблон: {template.name}')
            else:
                self.stdout.write(f'Шаблон уже существует: {template.name}')
        
        # Create default components
        components_data = [
            {'name': 'Магазин', 'component_type': 'shop', 'description': 'Модуль интернет-магазина с товарами и корзиной'},
            {'name': 'Блог', 'component_type': 'blog', 'description': 'Модуль для создания и управления статьями'},
            {'name': 'Галерея', 'component_type': 'gallery', 'description': 'Модуль для отображения изображений'},
            {'name': 'Контакты', 'component_type': 'contact', 'description': 'Модуль обратной связи и контактной информации'},
            {'name': 'SEO инструменты', 'component_type': 'seo', 'description': 'Инструменты для оптимизации сайта под поисковые системы'},
            {'name': 'Управление пользователями', 'component_type': 'users', 'description': 'Модуль регистрации, авторизации и управления пользователями'},
        ]
        
        for component_data in components_data:
            component, created = Component.objects.get_or_create(
                name=component_data['name'],
                defaults={
                    'component_type': component_data['component_type'],
                    'description': component_data['description']
                }
            )
            if created:
                self.stdout.write(f'Создан компонент: {component.name}')
            else:
                self.stdout.write(f'Компонент уже существует: {component.name}')
        
        self.stdout.write(
            self.style.SUCCESS('Инициализация завершена успешно!')
        )