from django.urls import path, include
from .views import ChallengeView

urlpatterns = [
    path('<str:challenge>', ChallengeView.as_view(), name='challenge-management'),
]