from django.db import models



class MalUrl(models.Model):
    url = models.URLField(max_length=120,help_text="Please use the following format http://example.com or https://example.com")


#changing start
#class MalFile(models.Model):
    #title = models.TextField(max_length=40, null=True)
    #imgfile = models.ImageField(null=True, upload_to="", blank=True)
    #content = models.TextField()

    #def __str__(self):
        #return self.title

#changing end
class Post(models.Model):
    id = models.AutoField(primary_key=True)
    postname = models.CharField(max_length=100)

class Article(models.Model):
    count = models.CharField(max_length=100)
    name = models.TextField()