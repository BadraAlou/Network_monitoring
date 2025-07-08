from django import forms
from app.models import User
from django.contrib.auth.forms import PasswordChangeForm

class UserSettingsForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['email', 'avatar']
