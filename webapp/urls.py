from django.urls import path
from django.conf.urls import handler500

handler500 = 'webapp.views.error_500'
handler404 = 'webapp.views.error_404'


from . import views
from . import files

#from webapp import views



urlpatterns = [
    path('', views.malurl_form, name='index'),
    path('download/<str:hash>/', views.file_download),
    #changing start
    #path('',files.malfile_form,name='file_index'),
    #path('upload/',views.upload,name='upload'),
    #changing end
]
