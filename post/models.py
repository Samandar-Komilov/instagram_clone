from django.db import models
from django.contrib.auth import get_user_model
from django.core.validators import FileExtensionValidator, MaxLengthValidator
from shared.models import BaseModel
from django.db.models import UniqueConstraint

User = get_user_model()

class Post(BaseModel):
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='posts')
    image = models.ImageField(upload_to='post_images', validators=[FileExtensionValidator(['jpeg', 'jpg', 'png'])])
    caption = models.TextField(validators=[MaxLengthValidator(2000)])
    # Juda katta text yozib serverni fall qilmasligi uchun validator

    class Meta:
        db_table = 'posts'
        verbose_name = "post"
        verbose_name_plural = "posts"

    def __str__(self):
        return f"{self.author} posted {self.caption[:10]}..."


class PostComment(BaseModel):
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="comments")
    comment = models.TextField()
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        related_name='child',
        null=True,
        blank=True
    )
    # parent - reply qiligan message qaysiga reply qilinganini bildirish uchun ishlatiladi

    def __str__(self):
        return f"{self.comment[:25]}... "
    

class PostLike(BaseModel):
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='likes')

    class Meta:
        # Bitta odam bir postga bittadan ko'p like bosmasligi uchun
        constraints = [
            UniqueConstraint(
                fields=['author', 'post'],
                name='PostLikeUnique'
            )
        ]

class CommentLike(BaseModel):
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    comment = models.ForeignKey(PostComment, on_delete=models.CASCADE, related_name='likes')

    class Meta:
        constraints = [
            UniqueConstraint(
                fields=['author', 'comment'],
                name='CommentLikeUnique'
            )
        ]