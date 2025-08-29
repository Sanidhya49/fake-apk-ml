from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import requests


@csrf_exempt
def scan_apk(request):
    if request.method != "POST" or "file" not in request.FILES:
        return JsonResponse({"error": "file required"}, status=400)
    f = request.FILES["file"]
    files = {"file": (f.name, f.read())}
    base = getattr(settings, "ML_SERVICE_URL", "http://localhost:9000")
    try:
        params = request.GET.dict()
        r = requests.post(f"{base}/scan", params=params, files=files, timeout=600)
        return JsonResponse(r.json(), status=r.status_code, safe=False)
    except Exception as e:
        return JsonResponse({"error": "ml_unreachable", "detail": str(e)}, status=502)


