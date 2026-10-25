terraform {
  required_version = "1.13.2"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.69.1"
    }
  }

  backend "s3" {
    encrypt      = true
    kms_key_id   = "alias/aws/s3"
    use_lockfile = true
  }
}
