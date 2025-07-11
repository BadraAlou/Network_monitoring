# Generated by Django 5.2.3 on 2025-06-27 06:14

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0007_alert_reseau_uid_blockedip_reseau_uid_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Version',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nom', models.CharField(choices=[('black_vault', 'Black Vault (Premium)'), ('dome', 'Dôme (Standard)'), ('aegis_sec', 'Aegis Sec (Moyen)')], max_length=20, unique=True)),
                ('description', models.TextField()),
                ('prix', models.DecimalField(decimal_places=2, max_digits=10)),
                ('fonctionnalités', models.TextField(help_text='Liste des fonctionnalités ou avantages de cette version')),
            ],
        ),
        migrations.AddField(
            model_name='user',
            name='version',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='app.version'),
        ),
    ]
