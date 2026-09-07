import os,shutil,subprocess
from pathlib import Path
import pytest
@pytest.mark.integration
@pytest.mark.requires_root
@pytest.mark.skipif(os.geteuid()!=0 or not os.path.exists("/dev/net/tun") or not shutil.which("ip") or not shutil.which("nft"),reason="requires root, TUN, iproute2 and nftables")
def test_real_namespace_tunnel():
    """Real TUN, two clients, ICMP/TCP/UDP, spoof rejection, rekey and reconnect."""
    script=Path(__file__).with_name("namespace_vpn.sh")
    subprocess.run([str(script)],check=True,timeout=180)
