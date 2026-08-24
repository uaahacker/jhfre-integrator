from django import forms

class CurrencyWidget(forms.TextInput):
    """
    Custom widget for currency fields with real-time formatting
    """
    def __init__(self, currency_symbol='$', *args, **kwargs):
        self.currency_symbol = currency_symbol
        super().__init__(*args, **kwargs)
        
    def build_attrs(self, base_attrs, extra_attrs=None):
        attrs = super().build_attrs(base_attrs, extra_attrs)
        attrs['data-field-type'] = 'currency'
        attrs['data-currency-symbol'] = self.currency_symbol
        attrs['class'] = f"{attrs.get('class', '')} currency-field".strip()
        attrs['placeholder'] = f'{self.currency_symbol}0.00'
        return attrs

class CurrencyField(forms.CharField):
    """
    Custom field for currency with formatting
    """
    def __init__(self, currency_symbol='$', *args, **kwargs):
        self.currency_symbol = currency_symbol
        kwargs['widget'] = CurrencyWidget(currency_symbol=currency_symbol)
        super().__init__(*args, **kwargs)
        
    def clean(self, value):
        if value:
            # Remove currency symbol and commas, keep only digits, decimal point, and minus sign
            import re
            cleaned_value = re.sub(r'[^\d.-]', '', str(value))
            return cleaned_value
        return value

def create_form_class(fields):
    """
    Dynamically create a Django form class based on JSON configuration.
    """
    class DynamicForm(forms.Form):
        for field_name, field_props in fields.items():
            field_type = field_props.get("type")
            label = field_props.get("label", field_name.capitalize())
            required = field_props.get("required", False)
            choices = field_props.get("choices", [])

            if field_type == "text":
                locals()[field_name] = forms.CharField(label=label, required=required)
            elif field_type == "number":
                locals()[field_name] = forms.IntegerField(label=label, required=required)
            elif field_type == "currency":
                currency_symbol = field_props.get("currencySymbol", "$")
                locals()[field_name] = CurrencyField(currency_symbol=currency_symbol, label=label, required=required)
            elif field_type == "textarea":
                locals()[field_name] = forms.CharField(widget=forms.Textarea, label=label, required=required)
            elif field_type == "select":
                locals()[field_name] = forms.ChoiceField(choices=[(choice, choice) for choice in choices], label=label, required=required)
            elif field_type == "radio":
                locals()[field_name] = forms.ChoiceField(widget=forms.RadioSelect, choices=[(choice, choice) for choice in choices], label=label, required=required)
            elif field_type == "checkbox":
                locals()[field_name] = forms.MultipleChoiceField(widget=forms.CheckboxSelectMultiple, choices=[(choice, choice) for choice in choices], label=label, required=required)

    return DynamicForm
