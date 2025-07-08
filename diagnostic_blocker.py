# diagnostic_blocker.py
from app.utils.enhanced_blocker import enhanced_blocker
import logging

logging.basicConfig(level=logging.INFO)


def run_diagnostic():
    """Diagnostic complet du système de blocage"""
    print("🔧 DIAGNOSTIC SYSTÈME DE BLOCAGE 2IEM")
    print("=" * 50)

    # Test privilèges
    if enhanced_blocker.is_admin:
        print("✅ Privilèges administrateur: OK")
    else:
        print("❌ Privilèges administrateur: MANQUANTS")
        print("   → Exécutez en tant qu'administrateur")

    # Test pare-feu
    firewall_ok = enhanced_blocker.check_firewall_status()
    if firewall_ok:
        print("✅ Pare-feu système: OK")
    else:
        print("❌ Pare-feu système: PROBLÈME")

    # Test méthodes disponibles
    print(f"📋 Méthodes de blocage: {len(enhanced_blocker.firewall_methods)}")
    for i, method in enumerate(enhanced_blocker.firewall_methods):
        print(f"   {i + 1}. {method.__name__}")

    # Test de blocage sur IP de test
    test_ip = "192.168.1.254"  # IP de test (à adapter)
    print(f"\n🧪 Test de blocage sur {test_ip}...")

    success = enhanced_blocker.force_block_ip(test_ip, "Test diagnostic")
    if success:
        print("✅ Test de blocage: RÉUSSI")

        # Débloquer immédiatement
        enhanced_blocker.unblock_ip(test_ip)
        print("✅ Test de déblocage: RÉUSSI")
    else:
        print("❌ Test de blocage: ÉCHEC")

    print("\n" + "=" * 50)
    print("Diagnostic terminé.")


if __name__ == "__main__":
    run_diagnostic()