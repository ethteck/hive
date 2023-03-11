# Generated by Django 4.1 on 2022-09-19 01:27

from django.db import migrations
import django_resized.forms


class Migration(migrations.Migration):
    dependencies = [
        ("coreapp", "0026_project_member_no_anons"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="project",
            name="icon_url",
        ),
        migrations.AddField(
            model_name="project",
            name="icon",
            field=django_resized.forms.ResizedImageField(
                crop=None,
                force_format="WEBP",
                keep_meta=False,
                null=True,
                quality=100,
                scale=1.0,
                size=[256, 256],
                upload_to="project_icons",
            ),
        ),
    ]
