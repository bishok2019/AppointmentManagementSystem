from django.urls import path
from . import views

urlpatterns = [
    path('visitor/', views.VisitorView.as_view(), name='get-visitor' ),
    # # path('visitor/<int:pk>', views.VisitorView.as_view(), name='get-visitor-detail' ),
    # # path('visitor/<int:pk>', views.ModifyVisitorView.as_view(), name='modify-visitor' ),
    path('', views.RegisterVisitorView.as_view(), name='register-visitor' ),
]