from django.urls import path
from . import views

urlpatterns = [
    path('auth/register/', views.register_user, name='register'),
    path('auth/login/', views.login_user, name='login'),
    path('api/users/<uuid:pk>/', views.get_user, name='user_detail'),
    path('api/organisations/', views.organisation_view,
         name='organisation_list'),
    path('api/organisations/<uuid:pk>/',
         views.get_organisation, name='organisation_detail'),
    path('api/organisations/', views.organisation_view,
         name='create_organisation'),
    path('api/organisations/<uuid:pk>/users/',
         views.add_user_to_organisation, name='add_user_to_organisation')
]
