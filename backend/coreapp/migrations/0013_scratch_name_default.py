# Generated by Django 3.2.6 on 2022-01-03 14:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('coreapp', '0012_alter_scratch_name'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='scratch',
            options={'ordering': ['-creation_time']},
        ),
        migrations.AlterField(
            model_name='scratch',
            name='name',
            field=models.CharField(default='Untitled', max_length=512),
        ),
    ]
