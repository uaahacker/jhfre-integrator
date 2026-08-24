from django import template

register = template.Library()

@register.filter
def get_dict_item(dictionary, key):
    """
    Template filter to get a value from a dictionary by key.
    Usage: {{ dictionary|get_dict_item:key }}
    """
    if not dictionary:
        return None
    return dictionary.get(key) 