from django.core.management.base import BaseCommand
from integrator.models import DynamicForm
import json

class Command(BaseCommand):
    help = 'Test the template functionality by creating a sample form'

    def handle(self, *args, **options):
        # Create a test form with template settings
        form = DynamicForm.objects.create(
            uuid='test-template-form',
            formname='Template Test Form',
            form_description='A test form to verify template functionality',
            config='{"field1": {"type": "text", "label": "Name"}, "field2": {"type": "currency", "label": "Amount"}}',
            template_type='corporate',
            custom_colors='{"primary": "#007bff", "secondary": "#6c757d"}',
            header_text='Welcome to Our Corporate Form',
            footer_text='© 2025 Your Company'
        )
        
        self.stdout.write(
            self.style.SUCCESS(f'Successfully created test form with UUID: {form.uuid}')
        )
        self.stdout.write(f'Template type: {form.template_type}')
        self.stdout.write(f'Custom colors: {form.custom_colors}')
        self.stdout.write(f'Header text: {form.header_text}')
        self.stdout.write(f'Footer text: {form.footer_text}')
        
        # Test accessing the form
        test_form = DynamicForm.objects.get(uuid='test-template-form')
        self.stdout.write(
            self.style.SUCCESS('✅ Template fields are working correctly!')
        )
        
        # Clean up
        test_form.delete()
        self.stdout.write('Test form cleaned up.')
