"""maldetect URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include,path
#changing start
from django.conf.urls.static import static
from django.conf import settings
from webapp import views
#changing end

urlpatterns = [
    path('admin/', admin.site.urls),
    path('',include('webapp.urls')),
    path('upload/',views.upload,name='upload'),
    path('upload_f/', views.uploadFile, name='uploadFile'),
    path('url_upload/', views.url_upload, name='url_upload'),
    path('adblock/', views.adblock, name='adblock'),
    path('download/<str:hash>/', views.file_download),
    # ============================ ocr ===================================
    path('uploadOcr/', views.uploadOcr, name='uploadOcr'),
    # ====================================================================
    
    ]

if settings.DEBUG:
    urlpatterns +=static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)