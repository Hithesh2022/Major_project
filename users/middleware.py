from django.utils.deprecation import MiddlewareMixin
from task import task_queue, network_detection_task, attack_detection_task, email_sending_task

class BackgroundTaskMiddleware(MiddlewareMixin):
    def __call__(self, request):
        # Enqueue tasks in the desired order
     if request is not None:
        task_queue.put(network_detection_task)
        task_queue.put(attack_detection_task)
        task_queue.put(email_sending_task)
        
        response = self.get_response(request)
        return response
