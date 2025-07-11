# Generated by Django 5.2.3 on 2025-06-26 18:33

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0006_alert_ia_analysis'),
    ]

    operations = [
        migrations.AddField(
            model_name='alert',
            name='reseau_uid',
            field=models.UUIDField(default=uuid.uuid4, editable=False),
        ),
        migrations.AddField(
            model_name='blockedip',
            name='reseau_uid',
            field=models.UUIDField(default=uuid.uuid4, editable=False),
        ),
        migrations.AddField(
            model_name='device',
            name='reseau_uid',
            field=models.UUIDField(default=uuid.uuid4, editable=False),
        ),
        migrations.AddField(
            model_name='honeypotlog',
            name='reseau_uid',
            field=models.UUIDField(default=uuid.uuid4, editable=False),
        ),
        migrations.AddField(
            model_name='log',
            name='reseau_uid',
            field=models.UUIDField(default=uuid.uuid4, editable=False),
        ),
        migrations.AddField(
            model_name='notification',
            name='reseau_uid',
            field=models.UUIDField(default=uuid.uuid4, editable=False),
        ),
        migrations.AddField(
            model_name='trafficlog',
            name='reseau_uid',
            field=models.UUIDField(default=uuid.uuid4, editable=False),
        ),
    ]
