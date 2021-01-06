# Generated by Django 3.0.5 on 2021-01-06 04:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0010_remove_requestpool_expire_on'),
    ]

    operations = [
        migrations.AddField(
            model_name='requestpool',
            name='is_active',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='requestpool',
            name='vehicle_no',
            field=models.CharField(default=1, max_length=20),
            preserve_default=False,
        ),
    ]
