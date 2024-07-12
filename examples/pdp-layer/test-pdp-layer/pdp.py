def check_authz(request, session):
    if 'Admins' in session.groups:
        return True, {}

    if 'BlogAdmins' in session.groups:
        if request.path.startswith('/blog/'):
            return True, {}

    return False, {}
