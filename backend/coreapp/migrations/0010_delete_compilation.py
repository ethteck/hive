# Generated by Django 3.2.4 on 2021-11-20 09:05

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('coreapp', '0009_remove_crud_from_compilation'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Compilation',
        ),
    ]
