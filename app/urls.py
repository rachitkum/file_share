from django.urls import path
from .views import *

urlpatterns = [
    path('signup/', SignupView.as_view()),
    path('verify-email/', VerifyEmailView.as_view()),
    path('login/', LoginView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('upload/', UploadFileView.as_view()),
    path('files/', ListFilesView.as_view()),
    path('download-file/<int:file_id>/', DownloadFileView.as_view()),
]
