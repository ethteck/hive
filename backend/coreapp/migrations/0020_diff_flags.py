# Generated by Django 4.0.3 on 2022-04-05 09:46

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("coreapp", "0019_scratch_preset"),
    ]

    operations = [
        migrations.AddField(
            model_name="compilerconfig",
            name="diff_flags",
            field=models.JSONField(blank=True, default=str),
        ),
        migrations.AddField(
            model_name="scratch",
            name="diff_flags",
            field=models.JSONField(blank=True, default=str),
        ),
    ]
