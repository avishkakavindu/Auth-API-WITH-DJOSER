from django.contrib import admin
from django.db.models import Exists, OuterRef
from .models import *


admin.site.register(UserAccount)
admin.site.register(PayhereDetails)
admin.site.register(RFID)


@admin.register(RFIDDetail)
class RFIDDetailAdmin(admin.ModelAdmin):
    list_display = ['get_rf_id', 'vehicle_no', 'engine_no', 'is_assigned']
    list_filter = ['is_assigned']
    search_fields = ['rf_id', 'user', 'is_assigned']

    def formfield_for_foreignkey(self, db_field, request, **kwargs):

        if db_field.name == "rf_id":
            kwargs["queryset"] = RFID.objects.filter(rfiddetail__isnull=True)
        return super(RFIDDetailAdmin, self).formfield_for_foreignkey(db_field, request, **kwargs)


