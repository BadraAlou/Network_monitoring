from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import *



@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('username', 'email', 'role', 'is_active', 'date_joined')
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Informations supplémentaires', {'fields': ('role', 'avatar')}),
    )

@admin.register(Device)
class DevicesAdmin(admin.ModelAdmin):
    list_display = ['ip_address','hostname','mac_address','os','status','last_seen']
    search_fields = ("hostname", "ip_address", "mac_address")
    list_filter = ("status",)

@admin.register(Alert)
class AlertsAdmin(admin.ModelAdmin):
    list_display = ['device','severity','description','alert_type','detected_on']
    list_filter = ("severity", "detected_on")
    search_fields = ("device__hostname", "alert_type")

@admin.register(Log)
class LogsAdmin(admin.ModelAdmin):
    list_display = ['device','event','scanned_by','scan_time']
    search_fields = ("device__hostname", "event")
    list_filter = ("scan_time",)

admin.site.register(TrafficLog)

admin.site.register(DeviceEvent)
admin.site.register(BlockedIP)