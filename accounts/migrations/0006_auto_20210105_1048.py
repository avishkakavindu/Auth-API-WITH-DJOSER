# Generated by Django 3.0.5 on 2021-01-05 05:18

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0005_auto_20210105_1037'),
    ]

    operations = [
        migrations.AlterField(
            model_name='rfiddetail',
            name='rf_id',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='accounts.RFID'),
        ),
    ]
