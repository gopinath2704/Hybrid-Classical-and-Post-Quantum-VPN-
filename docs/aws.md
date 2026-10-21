# Running the PQ-VPN server on AWS EC2

One small Ubuntu instance runs the server; `scripts/deploy-server.sh` performs the
install steps from [deployment.md](deployment.md). The validation gates in that
guide still apply: this is a research prototype.

## 1. AWS side (you, in the console or with the AWS CLI)

| Setting | Value |
|---|---|
| Region | closest to you |
| AMI | Ubuntu Server 26.04 LTS, x86_64 (tested baseline is CPython 3.14 on x86_64) |
| Instance type | `t3.small` (2 GB RAM; the liboqs build is slow on `t3.micro`) |
| Disk | 16 GB gp3 |
| Key pair | an existing or new SSH key pair |
| Metadata | IMDSv2 required |
| Elastic IP | allocate and associate, so the client's `server_host` does not change |

Security group, inbound only:

| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 22 | TCP | **your IP only** (`x.x.x.x/32`) | SSH |
| 51820 | TCP | `0.0.0.0/0` | PQ-VPN control channel (handshake) |
| 51820 | UDP | `0.0.0.0/0` | PQ-VPN data channel |

Do not open 8000 or any management port. Open 8443 (account API, HTTPS) only for
self-service onboarding, and only to trusted source IPs (`x.x.x.x/32`): with
`auto_approve = true` anyone who can register (registration needs an admin-issued invite
by default) gets tunnel access. Outbound: allow all (default).

Authorized clients live in `/var/lib/pqvpn/authorized/authorized_clients.json`
(directory `root:pqvpn 2770`); `deploy-server.sh` migrates a legacy
`/etc/pqvpn/authorized_clients.json` there and repoints both TOML files.

AWS CLI equivalent (replace the region, key name and your IP):

```bash
REGION=eu-west-2 KEY=pqvpn MYIP=$(curl -s https://checkip.amazonaws.com)/32
AMI=$(aws ssm get-parameter --region $REGION --query Parameter.Value --output text \
  --name /aws/service/canonical/ubuntu/server/26.04/stable/current/amd64/hvm/ebs-gp3/ami-id)
SG=$(aws ec2 create-security-group --region $REGION --group-name pqvpn \
  --description "PQ-VPN" --query GroupId --output text)
aws ec2 authorize-security-group-ingress --region $REGION --group-id $SG --protocol tcp --port 22 --cidr $MYIP
aws ec2 authorize-security-group-ingress --region $REGION --group-id $SG --protocol tcp --port 51820 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --region $REGION --group-id $SG --protocol udp --port 51820 --cidr 0.0.0.0/0
ID=$(aws ec2 run-instances --region $REGION --image-id $AMI --instance-type t3.small \
  --key-name $KEY --security-group-ids $SG \
  --metadata-options HttpTokens=required \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=16,VolumeType=gp3}' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=pqvpn}]' \
  --query 'Instances[0].InstanceId' --output text)
EIP=$(aws ec2 allocate-address --region $REGION --query AllocationId --output text)
aws ec2 wait instance-running --region $REGION --instance-ids $ID
aws ec2 associate-address --region $REGION --instance-id $ID --allocation-id $EIP
aws ec2 describe-addresses --region $REGION --allocation-ids $EIP --query 'Addresses[0].PublicIp' --output text
```

These create billable resources (instance, volume, Elastic IP). Tear down in section 5.

## 2. Client key (on your Linux client)

```bash
python3 -m venv .venv && .venv/bin/python -m pip install -c constraints-tested.txt .
.venv/bin/python -m vpn.cli client-key generate --kem   # v3 (protocol_version = 3)
scp -i pqvpn.pem config/client_identity_public.key ubuntu@<ELASTIC_IP>:/tmp/alice_public.key
```

Only the public key leaves the client.

## 3. Server install (on the instance)

```bash
ssh -i pqvpn.pem ubuntu@<ELASTIC_IP>
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/gopinath2704/hybrid-classical-and-post-quantum-vpn-.git pqvpn-src
cd pqvpn-src
sudo bash scripts/deploy-server.sh /tmp/alice_public.key alice
```

The script installs OS packages and native liboqs 0.16.0 (commit-verified), creates the
root-owned `/opt/pqvpn` tree and `pqvpn` service user, generates the server identity
(`/etc/pqvpn`, private key `0400`), installs `server.toml` (WAN interface auto-detected),
authorizes the client, runs `doctor server`, and starts `pqvpn-server`. It prints the
server fingerprint at the end. Run without arguments to install only.

Add more clients later:

```bash
cd /opt/pqvpn
sudo .venv/bin/python -m vpn.cli client authorize /tmp/bob_public.key --database /var/lib/pqvpn/authorized/authorized_clients.json --client-id bob
sudo systemctl restart pqvpn-server
```

## 4. Connect (on the client)

```bash
ssh -i pqvpn.pem ubuntu@<ELASTIC_IP> sudo cat /etc/pqvpn/server_identity_public.key > config/server_identity_public.key
sha256sum config/server_identity_public.key   # must equal the fingerprint the script printed
```

In `config/client.toml` set `server_host = "<ELASTIC_IP>"` and
`server_identity_fingerprint` to that fingerprint. Then:

```bash
.venv/bin/python -m vpn.cli doctor client --config config/client.toml
sudo -E .venv/bin/python -m vpn.cli client connect --config config/client.toml
curl -4 --max-time 10 https://checkip.amazonaws.com   # should print the Elastic IP
```

Then run the real-client gates in [deployment.md](deployment.md#setup-systemd-and-real-client-gates).

## 5. Tear down

```bash
aws ec2 terminate-instances --region $REGION --instance-ids $ID
aws ec2 wait instance-terminated --region $REGION --instance-ids $ID
aws ec2 release-address --region $REGION --allocation-id $EIP
aws ec2 delete-security-group --region $REGION --group-id $SG
```

An unattached Elastic IP is still billed, so release it.
