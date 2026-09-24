# Minimal network: one VPC, one public subnet, one IGW, one route table.
# Ring 2 (ADR-0007 §3): the Security Group is born with empty ingress. SSM dials
# out over 443; nothing needs to dial in. The two Wazuh ports (1514/1515) are the
# only planned exceptions, gated behind their own toggles (D-37) and scoped to the
# owner's IP, never 0.0.0.0/0.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "soc-ai-vpc"
  }
}

# Pinned (not left to auto-assignment): the data EBS volume (storage.tf) and the
# instance (compute.tf) must land in the same AZ as this subnet to attach.
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "soc-ai-public-subnet"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "soc-ai-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "soc-ai-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "instance" {
  name        = "soc-ai-instance-sg"
  description = "SOC-AI EC2 instance - ingress empty by default (Ring 2)"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "soc-ai-instance-sg"
  }
}

resource "aws_vpc_security_group_egress_rule" "https_out" {
  security_group_id = aws_security_group.instance.id
  description       = "Outbound HTTPS: SSM, CloudWatch, S3, Parameter Store, Slack/Telegram, image pulls"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "wazuh_agent" {
  count = var.enable_wazuh_agent_ingress ? 1 : 0

  security_group_id = aws_security_group.instance.id
  description       = "Wazuh agent session (1514) - D-37, scoped to owner IP"
  cidr_ipv4         = "${var.wazuh_agent_source_ip}/32"
  from_port         = 1514
  to_port           = 1514
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "wazuh_enrollment" {
  count = var.enable_wazuh_enrollment_ingress ? 1 : 0

  security_group_id = aws_security_group.instance.id
  description       = "Wazuh agent enrollment (1515) - D-37, open only during a host's enrollment window"
  cidr_ipv4         = "${var.wazuh_agent_source_ip}/32"
  from_port         = 1515
  to_port           = 1515
  ip_protocol       = "tcp"
}

# F-12 / D-39: S3 gateway endpoint. Free of charge; keeps S3 traffic off the IGW
# and enables future aws:SourceVpce bucket restrictions (never on the tfstate
# bucket - Terraform runs from the owner's laptop, outside the VPC).
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.public.id]

  tags = {
    Name = "soc-ai-s3-gateway-endpoint"
  }
}
