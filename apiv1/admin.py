from django.contrib import admin
from . import models

# Register your models here.


admin.site.register(models.Product)
admin.site.register(models.Version)
admin.site.register(models.ProductVersion)
admin.site.register(models.Vulnerability)
admin.site.register(models.Comment)