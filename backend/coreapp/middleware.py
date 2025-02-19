import logging
import re
from typing import Callable, Optional, TYPE_CHECKING, Union

from django.contrib import auth
from django.contrib.auth.models import User
from django.http.request import HttpRequest
from django.utils.timezone import now
from rest_framework.request import Request as DRFRequest
from rest_framework.response import Response

from .models.profile import Profile

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .models.github import GitHubUser


class AnonymousUser(auth.models.AnonymousUser):
    profile: Profile


if TYPE_CHECKING:

    class Request(DRFRequest):
        user: Union[User, AnonymousUser]
        profile: Profile

else:
    Request = DRFRequest


def disable_csrf(
    get_response: Callable[[HttpRequest], Response]
) -> Callable[[HttpRequest], Response]:
    def middleware(request: HttpRequest) -> Response:
        setattr(request, "_dont_enforce_csrf_checks", True)
        return get_response(request)

    return middleware

def request_needs_profile(req: Request):
    methods_paths = [
        ("GET", "/api/user"),
        ("GET", "/api/user/scratches"),
        ("POST", "/api/scratch"),
        ("POST", r"/api/scratch/[A-z0-9]+/fork"),
        ("POST", r"/api/scratch/[A-z0-9]+/claim"),
        ("POST", "/api/preset"),
    ]
    for method, path in methods_paths:
        if req.method == method and re.match(path, req.path ):
            return True

    return False

def set_user_profile(
    get_response: Callable[[HttpRequest], Response]
) -> Callable[[Request], Response]:
    """
    Makes sure that `request.profile` is always available, even for anonymous users.
    """

    def middleware(request: Request) -> Response:
        user_agent = request.headers.get("User-Agent")
        x_forwarded_for = request.headers.get("X-Forwarded-For", "n/a")

        # Avoid creating profiles for SSR or bots
        if user_agent is None or (
            "node" in user_agent
            or "undici" in user_agent
            or "Next.js Middleware" in user_agent
            or "python-requests" in user_agent
            or "curl" in user_agent
            or "YandexRenderResourcesBot" in user_agent
        ):
            request.profile = Profile()
            return get_response(request)

        profile: Optional[Profile] = None

        # Use the user's profile if they're logged in
        if not request.user.is_anonymous:
            profile = Profile.objects.filter(user=request.user).first()

        # Otherwise, use their session profile
        if not profile:
            id = request.session.get("profile_id")

            if isinstance(id, int):
                profile = Profile.objects.filter(id=id).first()
                if profile is not None:
                    profile_user = User.objects.filter(profile=profile).first()

                    if profile_user and request.user.is_anonymous:
                        request.user = profile_user

        # Otherwise, this is likely their first visit to the site
        if not profile and request_needs_profile(request):
            # Create a new profile
            profile = Profile()

            # And attach it to the logged-in user, if there is one
            if not request.user.is_anonymous:
                assert Profile.objects.filter(user=request.user).first() is None
                profile.user = request.user

            profile.save()
            request.session["profile_id"] = profile.id

            # Log profile creation to protect against misconfiguration or abuse
            logger.debug(
                "Made new profile: %s, User-Agent: %s, IP: %s, Endpoint: %s,",
                profile,
                user_agent,
                x_forwarded_for,
                request.path,
            )

        if profile:
            if profile.user is None and not request.user.is_anonymous:
                logger.info("%s vs %s ? %s", request.user, profile.user, request.user == profile.user)
                profile.user = request.user

            profile.last_request_date = now()
            profile.save()

        else:
            profile = Profile()
            logger.debug(
                "Made transient profile: %s, User-Agent: %s, IP: %s, Endpoint: %s",
                profile,
                user_agent,
                x_forwarded_for,
                request.path,
            )

        request.profile = profile

        return get_response(request)

    return middleware
