# Generated by Django 4.2.3 on 2023-07-16 14:07

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='auth_status',
            new_name='AUTH_STATUS',
        ),
        migrations.RenameField(
            model_name='user',
            old_name='auth_type',
            new_name='AUTH_TYPE',
        ),
    ]