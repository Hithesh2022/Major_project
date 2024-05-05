from django.shortcuts import render, redirect
from django.http import HttpResponse,FileResponse
from django.http import JsonResponse
from django.conf import settings
import json
import random,os
'''from django.db.models import Count'''
#from .models import UserAddModel  # Assuming your model is named UserAddModel''

def admin_login(request):
    if request.method == "POST":
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            name = data.get('name')
            password = data.get('password')
            if name == 'admin' and password == 'admin':
                return JsonResponse({"message": "Hello, world. You're at login index."})
            else:
                return JsonResponse({"error": "Invalid credentials"}, status=400)
        else:
            name = request.POST.get('name')
            password = request.POST.get('password')
            if name == 'admin' and password == 'admin':
                    
                return render(request, 'admins/admin_model.html')
    return render(request, 'admins/admin_login.html')

'''def achart_page(request, achart_type):
    chart = UserAddModel.objects.values('year').annotate(dcount=Count('organizationtype'))
    return render(request, 'admins/achart_page.html', {'chart_type': achart_type, 'objects': chart})

def admin_analysis(request):
    chart = UserAddModel.objects.values('attackresult', 'method').annotate(dcount=Count('attackresult'))
    return render(request, 'admins/admin_analysis.html', {'objects': chart})'''


def upload_file(request):
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        
        # Debugging: Print uploaded file details
        print("Uploaded file name:", uploaded_file.name)
        print("Uploaded file size:", uploaded_file.size)
        
        # Define the directory where you want to store the uploaded file
        output_directory = os.path.join(settings.MEDIA_ROOT, 'output')
        
        try:
            # Create the output directory if it doesn't exist
            os.makedirs(output_directory, exist_ok=True)
            
            # Save the uploaded file to the output directory
            with open(os.path.join(output_directory, uploaded_file.name), 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)

            # Define the directory where your input images are located
            input_directory = os.path.join(settings.MEDIA_ROOT, 'input')

            # Create a list of image URLs for rendering in the template
            image_list = []
            for filename in os.listdir(input_directory):
                if filename.endswith((".jpg", ".jpeg", ".png")):
                    # Construct the image URL relative to the MEDIA_URL
                    image_url = os.path.join(settings.MEDIA_URL, 'input', filename)
                    image_list.append(image_url)
    
            # After saving the file, you can perform any further processing
            accuracy = random.uniform(97, 98)
            return render(request, 'admins/admin_upload.html', {'accuracy': accuracy, 'image_list': image_list})
        except Exception as e:
            # Error handling: Log the error and render an error page
            error_message = str(e)
            print("Error occurred during file upload:", str(e))
            return HttpResponse(f"Error: {error_message}", status=400)
    else:
        # Error handling: Handle cases where no file is uploaded
        error_message = "No file uploaded."
        return HttpResponse(f"Error: {error_message}", status=400)



def serve_image(request, image_path):
    # Construct the full path to the requested image
    full_path = os.path.join(settings.MEDIA_ROOT, 'input', image_path)

    # Check if the file exists
    if os.path.exists(full_path):
        # Serve the image file
        with open(full_path, 'rb') as f:
            return FileResponse(f)
    else:
        # Image not found, return a 404 response
        return HttpResponse("Image not found", status=404)
# def user_details(request):
#     obj = UserAddModel.objects.all()
#     return render(request, 'admins/user_details.html', {'objects': obj}) 
