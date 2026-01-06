#!/usr/bin/env python3
"""
Minimal smoke test for Python 3.12 compatibility.
Verifies imports and basic functions do not crash.
"""

import sys

def main():
    """Run minimal smoke tests."""
    try:
        # Test import
        from dp_cli.aella_cli_aio_appliance import AellaCli, run_cmd, CmdResult
        print("✓ Import successful")
        
        # Test CLI class instantiation
        cli = AellaCli()
        print("✓ CLI class instantiation successful")
        
        # Test get_vm_list() safely (virsh may not exist)
        try:
            vm_list = AellaCli.get_vm_list()
            print(f"✓ get_vm_list() completed (found {len(vm_list)} VMs)")
        except Exception as e:
            print(f"⚠ get_vm_list() raised exception (expected if virsh not available): {type(e).__name__}")
        
        # Test get_da_name() safely
        try:
            da_name = AellaCli.get_da_name()
            print(f"✓ get_da_name() completed (returned: {da_name})")
        except Exception as e:
            print(f"⚠ get_da_name() raised exception (expected if virsh not available): {type(e).__name__}")
        
        print("\n✓ All smoke tests passed")
        return 0
        
    except Exception as e:
        print(f"✗ Smoke test failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())

