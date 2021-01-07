from rest_framework import status
from rest_framework.response import Response
from django.db.models.signals import pre_save
from django.dispatch import receiver
from .models import RFIDDetail
from .util import Util


@ receiver(pre_save, sender=RFIDDetail)
def assign_rfid(sender, instance, **kwargs):
    """ Signal send email upon assign of rfid """
    try:
        rfid_details = RFIDDetail.objects.select_related('user').get(pk=instance.pk)
        old_rf_id = rfid_details.rf_id
        name = rfid_details.user.name
        email = rfid_details.user.email
        vehicle_no = rfid_details.vehicle_no
        new_rf_id = instance.rf_id

        if instance.is_assigned:
            if old_rf_id is None and new_rf_id is not None:
                email_body = "Hi {},\nNew RFID tag assigned for the vehicle!\nRFID: {}\nVehicle No.: {}".format(name, new_rf_id, vehicle_no)

            elif new_rf_id is not None:
                email_body = "Hi {},\nNew RFID is assigned to your vehicle!\nOld RFID: {}\nRFID: {}\nVehicle No.: {}".format(name, old_rf_id, new_rf_id, vehicle_no)

            data = {
                'receiver': email,
                'email_body': email_body,
                'email_subject': 'RFID Assigned',
            }

            Util.send_email(data)
            context = {
                'Success': 'Email sent to user {}'.format(email)
            }

            return Response(context, status=status.HTTP_200_OK)
    except:
        pass


# pre_save.connect(assign_rfid, sender=RFIDDetail)
