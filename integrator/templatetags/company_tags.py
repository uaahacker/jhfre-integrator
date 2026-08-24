# from django import template
# from integrator.models import Company # Changed from sysbrix.models

# register = template.Library()


# @register.simple_tag
# def get_company_logo():
#     """
#     Returns company logo URL or name based on 'show_logo_as_text' setting.
#     """
#     try:
#         company = Company.objects.first()
#         if not company:
#             return {'type': 'text', 'value': 'Default Company'}
        
#         if company.show_logo_as_text or not company.logo:
#             return {'type': 'text', 'value': company.name}
#         else:
#             return {'type': 'image', 'value': company.logo.url}
    
#     except Company.DoesNotExist:
#         return {'type': 'text', 'value': 'Default Company'}
