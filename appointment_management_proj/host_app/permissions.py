# permissions.py
from rest_framework import permissions
from rest_framework.permissions import BasePermission

class IsUserType(BasePermission):
    allowed_types = []

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.user_type in self.allowed_types
        )

class IsAdmin(IsUserType):
    allowed_types = ['ADMIN']
    message = "Admin access required."

class IsManager(IsUserType):
    allowed_types = ['MANAGER']
    message = "Manager access required."

class IsStaff(IsUserType):
    allowed_types = ['STAFF']
    message = "Staff access required."

class IsAdminOrManager(IsUserType):
    allowed_types = ['ADMIN', 'MANAGER']
    message = "Admin or Manager access required."

class IsOwner(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.visiting_to == request.user

class IsAdminOrManagerOrOwner(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return (request.user.user_type in ['ADMIN', 'MANAGER']) or (obj.visiting_to == request.user)

class IsAllowedUserType(BasePermission):
    def has_permission(self, request, view):
        return (
            IsStaff().has_permission(request, view) or
            IsAdmin().has_permission(request, view) or
            IsAdminOrManager().has_permission(request, view) or
            IsAdminOrManagerOrOwner().has_permission(request, view) or
            IsManager().has_permission(request, view) or
            IsOwner().has_permission(request, view)
        )