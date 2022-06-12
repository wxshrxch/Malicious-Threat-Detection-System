from django import forms

from .models import MalUrl

#changing start
#from .models import MalFile
#changing end

class MalUrlForm(forms.ModelForm):
    class Meta:
        model = MalUrl
        exclude = []

class UploadFileForm(forms.Form):
    title = forms.CharField(max_length=50)
    file = forms.FileField()

