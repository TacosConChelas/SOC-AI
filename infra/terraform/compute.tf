# The instance: cattle, not a pet (Infrastructure.md §1, Principle 1). Blocked
# by the pending vCPU quota for G instances (0 approved as of this writing) -
# this file is written and planned, but not applied.
#
# AMI: Deep Learning Base OSS Nvidia Driver GPU AMI (Amazon Linux 2023). Chosen
# over the framework-bundled DLAMI variants (PyTorch, TensorFlow, ...): this
# project brings its own runtime (Ollama in Docker) and only needs the NVIDIA
# driver/CUDA + Docker + NVIDIA Container Toolkit that ship on the Base OSS
# variant - the same "fragile first boot" argument from ADR-0007 §6, with a
# smaller image.

data "aws_ami" "dlami_gpu" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Deep Learning Base OSS Nvidia Driver GPU AMI (Amazon Linux 2023) *"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "main" {
  ami                    = data.aws_ami.dlami_gpu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.instance.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name
  ebs_optimized          = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # IMDSv2 required (Ring 2, ADR-0007 §3)
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 30
    encrypted   = true
    kms_key_id  = aws_kms_key.project.arn
  }

  # First boot ONLY (Infrastructure.md §6.1): mount /data if virgin, install the
  # CloudWatch Agent as a host systemd service. Nothing else - no repo clone, no
  # stack start (Principle 2: Terraform provisions, the owner operates).
  user_data = <<-EOT
    #!/bin/bash
    set -euo pipefail

    MOUNT_POINT=/data
    DEVICE="/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_$(echo "${aws_ebs_volume.data.id}" | tr -d '-')"

    if ! blkid "$DEVICE" >/dev/null 2>&1; then
      mkfs.ext4 "$DEVICE"
    fi

    mkdir -p "$MOUNT_POINT"
    grep -q "$DEVICE" /etc/fstab || echo "$DEVICE $MOUNT_POINT ext4 defaults,nofail 0 2" >> /etc/fstab
    mount -a

    # Docker, Compose and the NVIDIA Container Toolkit ship with this AMI.

    yum install -y amazon-cloudwatch-agent
    systemctl enable --now amazon-cloudwatch-agent
  EOT

  tags = {
    Name = "soc-ai-instance"
  }
}

resource "aws_volume_attachment" "data" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.main.id
}
