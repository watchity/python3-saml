import os

from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseServerError
from django.shortcuts import render, redirect

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils


def init_saml_auth(req, provider):
    saml_folder = os.path.join(settings.SAML_BASE_DIR, provider)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=saml_folder)
    return auth


def prepare_django_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    result = {
        "https": "on" if request.is_secure() else "off",
        "http_host": request.META["HTTP_HOST"],
        "script_name": request.META["PATH_INFO"],
        "get_data": request.GET.copy(),
        "post_data": request.POST.copy(),
    }
    return result


def index(request):
    paint_logout = False
    attributes = None

    if "samlUserdata" in request.session:
        paint_logout = True
        attributes = request.session["samlUserdata"].items()

    return render(request, "index.html", {"paint_logout": paint_logout, "attributes": attributes})


def metadata(request, provider=None):
    saml_folder = os.path.join(settings.SAML_BASE_DIR, provider)
    saml_settings = OneLogin_Saml2_Settings(settings=None, custom_base_path=saml_folder, sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = HttpResponse(content=metadata, content_type="text/xml")
    else:
        resp = HttpResponseServerError(content=", ".join(errors))

    return resp


def sso(request, provider=None):
    req = prepare_django_request(request)
    auth = init_saml_auth(req, provider)
    return HttpResponseRedirect(auth.login(return_to=f"http://localhost:8000"))


def acs(request, provider=None):
    req = prepare_django_request(request)
    auth = init_saml_auth(req, provider)

    request_id = None

    if "AuthNRequestID" in request.session:
        request_id = request.session["AuthNRequestID"]

    auth.process_response(request_id=request_id)
    errors = auth.get_errors()
    not_auth_warn = not auth.is_authenticated()

    if not errors:
        if "AuthNRequestID" in request.session:
            del request.session["AuthNRequestID"]

        request.session["samlUserdata"] = auth.get_attributes()
        request.session["samlNameId"] = auth.get_nameid()
        request.session["samlNameIdFormat"] = auth.get_nameid_format()
        request.session["samlNameIdNameQualifier"] = auth.get_nameid_nq()
        request.session["samlNameIdSPNameQualifier"] = auth.get_nameid_spnq()
        request.session["samlSessionIndex"] = auth.get_session_index()

    elif auth.get_settings().is_debug_active():
        error_reason = auth.get_last_error_reason()
        return render(request, "index.html", {"error_reason": error_reason, "errors": errors, "not_auth_warn": not_auth_warn})

    if "RelayState" in req["post_data"] and OneLogin_Saml2_Utils.get_self_url(req) != req["post_data"]["RelayState"]:
        # To avoid 'Open Redirect' attacks, before execute the redirection confirm
        # the value of the req['post_data']['RelayState'] is a trusted URL.
        return HttpResponseRedirect(auth.redirect_to(req["post_data"]["RelayState"]))

    return redirect(index)


def slo(request, provider=None):
    req = prepare_django_request(request)
    auth = init_saml_auth(req, provider)

    name_id = session_index = name_id_format = name_id_nq = name_id_spnq = None
    if "samlNameId" in request.session:
        name_id = request.session["samlNameId"]
    if "samlSessionIndex" in request.session:
        session_index = request.session["samlSessionIndex"]
    if "samlNameIdFormat" in request.session:
        name_id_format = request.session["samlNameIdFormat"]
    if "samlNameIdNameQualifier" in request.session:
        name_id_nq = request.session["samlNameIdNameQualifier"]
    if "samlNameIdSPNameQualifier" in request.session:
        name_id_spnq = request.session["samlNameIdSPNameQualifier"]

    return HttpResponseRedirect(auth.logout(return_to="http://localhost:8000/", name_id=name_id, session_index=session_index, nq=name_id_nq, name_id_format=name_id_format, spnq=name_id_spnq))


def sls(request, provider=None):
    req = prepare_django_request(request)
    auth = init_saml_auth(req, provider)

    request_id = None

    if "LogoutRequestID" in request.session:
        request_id = request.session["LogoutRequestID"]

    dscb = lambda: request.session.flush()
    url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)

    errors = auth.get_errors()
    if errors:
        print(f"Errors: {errors}")

    if "RelayState" in req["get_data"] and OneLogin_Saml2_Utils.get_self_url(req) != req["get_data"]["RelayState"]:
        # To avoid 'Open Redirect' attacks, before execute the redirection confirm
        # the value of the req['get_data']['RelayState'] is a trusted URL.
        return HttpResponseRedirect(auth.redirect_to(req["get_data"]["RelayState"]))


def player_sso(request, provider=None, player_uuid=None):
    if "samlNameId" in request.session:
        attrs = request.session["samlUserdata"]
        import pdb; pdb.set_trace()
        user_name = attrs["Name"]
        user_email = attrs["Email"]
        return render(request, "player.html", {"player_uuid": player_uuid, "user_name": user_name, "user_email": user_email})
    else:
        req = prepare_django_request(request)
        auth = init_saml_auth(req, provider)
        return HttpResponseRedirect(auth.login(return_to=f"http://localhost:8000/player_sso/{provider}/{player_uuid}/"))
