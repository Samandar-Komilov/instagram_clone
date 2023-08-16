from django.urls import path
from . import views

urlpatterns = [
    path('posts/', views.PostListAPIView.as_view()),
    path('posts/create/', views.PostCreateAPIView.as_view()),
    path('posts/<uuid:pk>/', views.PostRetrieveUpdateDestroyAPIView.as_view()),
    path('posts/<uuid:pk>/comments/', views.PostCommentListAPIView.as_view()),
    path('posts/<uuid:pk>/comments/create/', views.PostCommentCreateAPIView.as_view()),
]


"""
Postmanda Create check qilish uchun Login qilinib access token olinadi
"""