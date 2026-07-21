from django.contrib import admin
from .models import *

admin.site.register(PacketLog)

admin.site.register(Threat)

admin.site.register(Alert)

admin.site.register(SystemStatus)