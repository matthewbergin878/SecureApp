from django.http import HttpResponseRedirect, JsonResponse
from django.db.models import F
from django.urls import reverse
from django.shortcuts import render, get_object_or_404
from django.template import loader
from django.contrib.auth.decorators import login_required, user_passes_test
import requests
import re
from urllib.parse import urlparse

def ssrf(request):
    url = request.GET.get('url')
    if not url: #check for url parameter
        return JsonResponse({'error': 'URL parameter is required'}, status=400)
    allowed_domains = ['example.com', 'google.com'] #whitelist domains that can be searched
    domain_group = "|".join(allowed_domains)
    regex = rf"\Awww[.]({domain_group})\Z"
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.hostname: #ensure it's a valid url
        return JsonResponse({'error': 'URL is not allowed'}, status=403)
    if parsed_url.scheme != "https": #ensure url uses secure https
        return JsonResponse({'error': 'URL must use https'}, status=403)
    if not re.search(regex, parsed_url.netloc): #ensure domain is one of the whiteliste done
        return JsonResponse({'error': 'URL is not allowed'}, status=403)
    try:
        #Add the custom header to simulate an internal request
        response = requests.get(url, headers={'X-Internal-Request': 'true'}, timeout=5, allow_redirects=False) #fetch valid resource, block redirects
        response.raise_for_status()
        return JsonResponse({'content': response.text}) 
    except requests.exceptions.RequestException as e:
        return JsonResponse({'error': str(e)}, status=500)

def internal(request):
    if request.headers.get('X-Internal-Request') != 'true': #check for internal request header
        return JsonResponse({'error': 'Access denied'}, status=403)
    if request.META.get('REMOTE_ADDR') not in ['127.0.0.1', '::1']: #check that request originated from the server
        #will always be true since we are running it locally
        return JsonResponse({'error': 'Access denied'}, status=403)
    #if the request was internal, return the secret resource
    return JsonResponse({'secret': 'This is a sensitive internal resource'})
