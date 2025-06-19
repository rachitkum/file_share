from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import get_object_or_404
from django.core.signing import Signer, BadSignature
from django.http import FileResponse
from .models import User, File
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
signer = Signer()

@method_decorator(csrf_exempt, name='dispatch')
class SignupView(APIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        role = request.data.get("role")
        if not all([email, password, role]):
            return Response({"error": "Missing fields"}, status=400)
        if User.objects.filter(email=email).exists():
            return Response({"error": "Email exists"}, status=400)
        user = User.objects.create_user(email=email, role=role, password=password)
        token = signer.sign(email)
        url = f"http://localhost:8000/api/verify-email/?token={token}"
        return Response({"message": "Signup success", "verification_url": url})

class VerifyEmailView(APIView):
    def get(self, request):
        token = request.GET.get("token")
        try:
            email = signer.unsign(token)
            user = User.objects.get(email=email)
            user.is_active = True
            user.save()
            return Response({"message": "Email verified"})
        except BadSignature:
            return Response({"error": "Invalid token"}, status=400)

@method_decorator(csrf_exempt, name='dispatch')
class LoginView(APIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response({"error": "Missing credentials"}, status=400)

        user = authenticate(request, email=email, password=password)
        if user and user.is_active:
            token, _ = Token.objects.get_or_create(user=user)
            return Response({
                "message": "Login success",
                "token": token.key
            })
        return Response({"error": "Invalid credentials"}, status=401)

class LogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({"message": "Logged out"})

class UploadFileView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if request.user.role != 'ops':
            return Response({"error": "Unauthorized"}, status=403)

        uploaded = request.FILES.get('file')
        if not uploaded:
            return Response({"error": "No file"}, status=400)

        ftype = uploaded.name.split('.')[-1].lower()
        if ftype not in ['docx', 'pptx', 'xlsx','pdf','csv']:
            return Response({"error": "Invalid type"}, status=400)


        File.objects.create(uploader=request.user, file=uploaded, filename=uploaded.name)
        return Response({"message": "File uploaded"})

class ListFilesView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != 'client':
            return Response({"error": "Unauthorized"}, status=403)

        files = File.objects.all().values('id', 'filename', 'upload_ts')
        return Response(list(files))

class DownloadFileView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, file_id):  # <-- now matches URLConf
        if request.user.role != 'client':
            return Response({"error": "Unauthorized"}, status=403)

        try:
            file = get_object_or_404(File, pk=file_id)
            return FileResponse(file.file, as_attachment=True, filename=file.filename)
        except:
            return Response({"error": "Invalid or expired link"}, status=400)