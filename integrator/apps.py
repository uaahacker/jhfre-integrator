from django.apps import AppConfig


class IntegratorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'integrator'
    
    def ready(self):
        """Import signals when Django starts"""
        import integrator.signals





