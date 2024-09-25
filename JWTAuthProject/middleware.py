from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.response import Response
from rest_framework import status
from django.utils.translation import gettext_lazy as _
from rest_framework.renderers import JSONRenderer

# Function to get a new access token using the refresh token
def get_new_access_token(refresh_token):
    try:
        print(1)
        refresh = RefreshToken(refresh_token)
        new_access_token = refresh.access_token
        return str(new_access_token)
    except Exception:
        return None

# Function to check if the access token is expired and refresh it
def check_and_refresh_token(request):
    access_token = request.headers.get('Authorization', None)
    refresh_token = request.headers.get('X-Refresh-Token', None)

    if access_token:
        access_token = access_token.split(' ')[1]  # Remove 'Bearer ' part
        try:
            AccessToken(access_token)  # Validate the access token
        except Exception:
            # Access token expired, attempt to refresh using the refresh token
            if refresh_token:
                new_access_token = get_new_access_token(refresh_token)
                if new_access_token:
                    return new_access_token
                else:
                    return Response(
                        {'error': _('Both tokens expired. Please log in again.')}, 
                        status=status.HTTP_401_UNAUTHORIZED
                    )
            else:
                return Response(
                    {'error': _('Access token expired and no refresh token provided.')}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
    return None

class JWTRefreshMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Check if tokens need to be refreshed
        new_access_token = check_and_refresh_token(request)

        # Return error response if both tokens are expired
        if isinstance(new_access_token, Response):
            return new_access_token

        # If a new access token is generated, inject it into the request headers
        if new_access_token:
            request.META['HTTP_AUTHORIZATION'] = f'Bearer {new_access_token}'

        return None  # Proceed to the view if access token is valid or refreshed

    def process_response(self, request, response):
        # Ensure the response is rendered in JSON format
        if not hasattr(response, 'accepted_renderer'):
            response.accepted_renderer = JSONRenderer()
            response.accepted_media_type = "application/json"
            response.renderer_context = {}
            response.render()  # Render the response content

        # Only modify the response headers after it is fully rendered
        if 'HTTP_AUTHORIZATION' in request.META:
            access_token = request.META['HTTP_AUTHORIZATION'].split(' ')[1]
            response['New-Access-Token'] = access_token 
        return response

