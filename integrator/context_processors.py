from .models import Company

def company_logo_context(request):
    try:
        company = Company.objects.first()
        if not company:
            return {'company_logo': {'type': 'text', 'value': 'Default Company'}}

        if company.show_logo_as_text or not company.logo:
            return {'company_logo': {'type': 'text', 'value': company.name}}
        else:
            return {'company_logo': {'type': 'image', 'value': company.logo.url}}
    
    except Company.DoesNotExist:
        return {'company_logo': {'type': 'text', 'value': 'Default Company'}}
