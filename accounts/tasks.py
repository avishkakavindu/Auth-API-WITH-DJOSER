# from background_task import background
# from .models import RequestPool
#
#
# @background(schedule=60)
# def update_request_status(request_id):
#     """ lookup requestpool object by id set status to deactivated"""
#     req = RequestPool.objects.get(pk=request_id)
#     req.is_active=False
#     req.save()
#     print("\nBackground task queued\n")
