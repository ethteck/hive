# Generated by Django 4.2 on 2023-05-03 09:03

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("coreapp", "0030_replace_ps1_gcc263_with_psyq36"),
    ]

    operations = [
        migrations.AlterField(
            model_name="scratch",
            name="diff_label",
            field=models.CharField(blank=True, max_length=1024),
        ),
        migrations.AlterField(
            model_name="scratch",
            name="name",
            field=models.CharField(default="Untitled", max_length=1024),
        ),
    ]
