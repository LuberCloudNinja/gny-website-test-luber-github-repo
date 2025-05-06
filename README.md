# Cloud-Native 3-Tier Web App for GNY Using AWS CDK Pipelines & GitLab/GitHub CI/CD

## Overview
This project delivers a scalable, secure, and fully automated cloud-native web application for **GNY (Group Health Incorporated)**, built on the AWS platform using modern DevSecOps best practices.

Designed as a **production-grade 3-tier architecture**, it leverages Infrastructure as Code (IaC) using **AWS CDK**, and a dual CI/CD strategy split between **GitHub for infrastructure** and **GitLab for application deployment**. The system supports highly available services, strict network security, and rapid deployments across multiple environments (dev, test, staging, prod).

---

## Architecture Highlights

### CI/CD Pipelines
- **Infrastructure Pipeline** (GitHub → AWS CDK Pipelines → CodeBuild + CloudFormation)
- **Application Pipeline** (GitLab → Build → Test → Deploy to ECS)
- Environment-specific automation using parameterized CDK stacks

### Frontend Layer
- **Amazon CloudFront** for dynamic content caching and global delivery
- **Application Load Balancer (ALB)** across multiple AZs with cross-zone load balancing
- **AWS Prefix Lists** to restrict access to CRN-approved IPs via the Core Enterprise Network (CEN)

### Application Layer
- **Amazon ECS (Fargate)** for fully serverless microservice deployment
- **Memcached** for in-memory session caching and performance optimization
- **Secure IAM roles** and fine-grained security groups for each containerized service

### Database Layer
- **Amazon RDS (Multi-AZ)** backend with failover support
- **RDS Proxy** for connection pooling and resilient app/database connectivity
- Secrets managed via **AWS SSM Parameter Store**

---

## Environments
The architecture supports full isolation across environments:
- **Development**
- **Test** (dedicated QA stage with automated testing)
- **Staging**
- **Production**

Each stack has its own CI/CD flow, configuration, networking, and IAM.

---

## Technologies Used
- **AWS CDK (Python)**
- Amazon CloudFront, ALB, ECS Fargate, RDS, RDS Proxy, Memcached
- GitHub, GitLab CI/CD
- AWS CodePipeline, CodeBuild, CloudFormation
- Amazon VPC, Prefix Lists, Security Groups, SSM
- CloudWatch, Fluent Bit (optional for logging)

---

## Deployment

### Prerequisites
- AWS CLI configured
- CDK CLI installed
- Node.js & npm installed

### Bootstrap & Deploy
```bash
cdk bootstrap
cdk deploy --all
# Welcome to your CDK Python project!
# Cloud-Native 3-Tier Web App for GNY Using AWS CDK Pipelines & GitLab/GitHub CI/CD

## Overview
This project delivers a scalable, secure, and fully automated cloud-native web application for **GNY (Group Health Incorporated)**, built on the AWS platform using modern DevSecOps best practices.

Designed as a **production-grade 3-tier architecture**, it leverages Infrastructure as Code (IaC) using **AWS CDK**, and a dual CI/CD strategy split between **GitHub for infrastructure** and **GitLab for application deployment**. The system supports highly available services, strict network security, and rapid deployments across multiple environments (dev, test, staging, prod).

---

## Architecture Highlights

### CI/CD Pipelines
- **Infrastructure Pipeline** (GitHub → AWS CDK Pipelines → CodeBuild + CloudFormation)
- **Application Pipeline** (GitLab → Build → Test → Deploy to ECS)
- Environment-specific automation using parameterized CDK stacks

### Frontend Layer
- **Amazon CloudFront** for dynamic content caching and global delivery
- **Application Load Balancer (ALB)** across multiple AZs with cross-zone load balancing
- **AWS Prefix Lists** to restrict access to CRN-approved IPs via the Core Enterprise Network (CEN)

### Application Layer
- **Amazon ECS (Fargate)** for fully serverless microservice deployment
- **Memcached** for in-memory session caching and performance optimization
- **Secure IAM roles** and fine-grained security groups for each containerized service

### Database Layer
- **Amazon RDS (Multi-AZ)** backend with failover support
- **RDS Proxy** for connection pooling and resilient app/database connectivity
- Secrets managed via **AWS SSM Parameter Store**

---

## Environments
The architecture supports full isolation across environments:
- **Development**
- **Test** (dedicated QA stage with automated testing)
- **Staging**
- **Production**

Each stack has its own CI/CD flow, configuration, networking, and IAM.

---

## Technologies Used
- **AWS CDK (TypeScript)**
- Amazon CloudFront, ALB, ECS Fargate, RDS, RDS Proxy, Memcached
- GitHub, GitLab CI/CD
- AWS CodePipeline, CodeBuild, CloudFormation
- Amazon VPC, Prefix Lists, Security Groups, SSM
- CloudWatch, Fluent Bit (optional for logging)

---

## Deployment

### Prerequisites
- AWS CLI configured
- CDK CLI installed
- Node.js & npm installed

### Bootstrap & Deploy
```bash
cdk bootstrap
cdk deploy --all
This is a blank project for CDK development with Python.

The `cdk.json` file tells the CDK Toolkit how to execute your app.

This project is set up like a standard Python project.  The initialization
process also creates a virtualenv within this project, stored under the `.venv`
directory.  To create the virtualenv it assumes that there is a `python3`
(or `python` for Windows) executable in your path with access to the `venv`
package. If for any reason the automatic creation of the virtualenv fails,
you can create the virtualenv manually.

To manually create a virtualenv on MacOS and Linux:

```
$ python3 -m venv .venv
```

After the init process completes and the virtualenv is created, you can use the following
step to activate your virtualenv.

```
$ source .venv/bin/activate
```

If you are a Windows platform, you would activate the virtualenv like this:

```
% .venv\Scripts\activate.bat
```

Once the virtualenv is activated, you can install the required dependencies.

```
$ pip install -r requirements.txt
```

At this point you can now synthesize the CloudFormation template for this code.

```
$ cdk synth
```

To add additional dependencies, for example other CDK libraries, just add
them to your `setup.py` file and rerun the `pip install -r requirements.txt`
command.

## Useful commands

 * `cdk ls`          list all stacks in the app
 * `cdk synth`       emits the synthesized CloudFormation template
 * `cdk deploy`      deploy this stack to your default AWS account/region
 * `cdk diff`        compare deployed stack with current state
 * `cdk docs`        open CDK documentation

Enjoy!
