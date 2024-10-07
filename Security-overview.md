# SECURITY
- Infrastructure security is the process of protecting the hardware, software, networks, and other components of an organization’s IT infrastructure from security threats. 
- Infrastructure security includes a range of technologies and policies, such as firewalls, intrusion detection systems, and access controls.

**A) PHASE 1: Infrastructure provisioning / configuration**
## a) Terraform security:
**i) Versioning and Release management:**
- Use versioning and VCS  to manage terraform configurations and track changes over time
- Follow semantic version conventions for terraform modules and releases.
- Don't commit the `.tfstate` file in VCS
**ii) State management:**
- Store state files remotely ina shared location
- Use remote state locking to prevent concurrent access and potential data corruption
- Regularly backup terraform state files and implement disaster recovery procedures.
**iii) Modularization:**
- Organise terraform code into reusable modules
- use modules to encapsulate common configurations and promote code reuse across projects
- Parameterize modules to make them flexible and configurable for different use cases.
**iv) Variable management:**
- Use variables to parameterize terraform configurations and make them reusable
- Define variable defaults and validation rules to ensure proper usage
- Store sensitive or environment specific variables securely using terraform input variable mechanisms or external secret managers
**v) Code review and testing:**
- conduct code reviews to ensure adherence to best practices, consistency and quality
- Implement automated tests to detect syntax errors, formatting issues and potential resource conflicts.
- Integrate terraform with CICD pipelines to automate testing, validation and deployment processes
**vi) Monitoring and maintenance:**
- Monitor terraform deployments and infrastructure changes using logging, monitoring and alerting tools
- implement automated backups and disaster recovery procedures to terraform state files and infrastructure resources
- Stay tunes for terraform updates, releases and best practices through official documentation.
**vii) Dependency management:**
- Explicitly define dependencies between resources using terraform's resource attributes and expressions
- Use terraform interpolation syntax to reference attributes from other resources
- leverage implicit dependencies to ensure resources are created and updated in the correct order
**viii) Security and complaince:**
- Follow security best practices for managing access to terraform configurations and state files.
- Implement role based access control (RBAC) and least privilege principles to restrict access to sensitive resources or operations.
- Regularly review and audit terraform configurations for compliance with security policies and industry regulations.
**x) Secret management**
- Store sensitive data iin external secret management tools
- Use environment variables in CICD pipelines
  
# b) Configuration management:
  - Secrets / use ansible secret manager- ansible vault
  - don't expose sensitive data in ansible outputs
  - avoid single target login names / using generic names eg admin 
# c) Host hardening:
   - Choice of your operating system
   - Non essential processes - /etc/init.d
   - Host based firewalling (SG, ACL, NACL)
   - Allow / open required ports
   - Use custom ports instead of Default ports 
# d) Private subnets: closing our resources to the public
   - Use private networks  for our resources
   - Configure `loadBalancer` to direct or control traffic from the internet to resources
   - Use security groups as firewalls around resources in our VPCs.
   - Use RBAC to control entry into our clusters or resources
   - Configure access entries (EKS) for authentication and authorization in to EKS


**B) PHASE 2: Build time security**

### a) Git / Git Hub DVCS:

# 1. Access Control:
- **Limit Access**: Only give access to those who absolutely need it. Use the principle of least privilege.
- **Role-Based Access Control (RBAC)**: Implement roles with specific permissions tailored to user needs.

# 2. Authentication
- **Strong Authentication Methods**: Use SSH keys or personal access tokens instead of passwords for Git operations.
- **Two-Factor Authentication (2FA)**: Enable 2FA on platforms like GitHub, GitLab, or Bitbucket to add an extra layer of security.

# 3. Encryption
- **Transport Layer Security (TLS)**: Ensure that data in transit is encrypted using HTTPS or SSH.
- **Repository Encryption**: Consider encrypting sensitive files in the repository itself using tools like Git-crypt.

# 4. Secrets Management
- **Avoid Hardcoding Secrets**: Do not store sensitive information (API keys, passwords) directly in the codebase.
- **Use Environment Variables**: Manage secrets through environment variables or secret management tools.

# 5. Auditing and Monitoring
- **Audit Logs**: Regularly review access and activity logs for suspicious behavior.
- **Automated Monitoring Tools**: Use tools that monitor repository changes and alert for unauthorized access.

# 6. Branch Protection
- **Protected Branches**: Set up rules to protect critical branches (e.g., `main` or `master`) from direct pushes, requiring pull requests and reviews instead.
- **Require Reviews**: Implement mandatory code reviews to catch issues before merging.

# 7. Regular Updates and Patching
- **Keep Tools Updated**: Regularly update Git clients, libraries, and associated tools to protect against known vulnerabilities.
- **Monitor for Vulnerabilities**: Stay informed about vulnerabilities in Git and third-party tools and apply patches promptly.

# 8. Backups
- **Regular Backups**: Implement a robust backup strategy for repositories to protect against data loss.
- **Test Restores**: Regularly test backup restores to ensure data integrity and availability.

# 9. Education and Training
- **Developer Awareness**: Train developers on secure coding practices and the importance of Git security.
- **Phishing Awareness**: Educate users about phishing attacks that may target Git credentials.

# 10. Repository Hygiene
- **Clean Up History**: Regularly clean the repository’s history to remove sensitive data. Tools like `git filter-repo` can help.
- **Use `.gitignore`**: Maintain a proper `.gitignore` file to avoid committing sensitive files or directories.

# b) Dealing with images:

### 1. **Use Official and Trusted Images**
- **Base Images**: Start from official images provided by trusted sources (e.g., Docker Hub, vendor repositories).
- **Minimal Images**: Use minimal base images (e.g., Alpine) to reduce the attack surface.

### 2. **Regularly Update Images**
- **Stay Updated**: Regularly pull the latest versions of base images and rebuild your images to include security patches.
- **Automated Scans**: Use tools like Trivy or Clair to automatically scan images for vulnerabilities.

### 3. **Least Privilege Principle**
- **User Permissions**: Avoid running applications as the root user inside containers. Specify a non-root user in your Dockerfile using the `USER` directive.
- **Limit Capabilities**: Use Docker’s capability controls to drop unnecessary Linux capabilities from containers.

### 4. **Immutable Infrastructure**
- **Immutable Images**: Treat images as immutable artifacts. Avoid modifying running containers; instead, create a new image for changes.
- **Version Control**: Tag images with version numbers and use them consistently to avoid unexpected changes.

### 5. **Secure Secrets Management**
- **Avoid Hardcoding Secrets**: Don’t store sensitive data (e.g., API keys) in image layers. Use Docker secrets or environment variables instead.
- **External Secrets Management**: Integrate with external secret management solutions like HashiCorp Vault or AWS Secrets Manager.

### 6. **Network Security**
- **Use Private Networks**: Limit container communication using Docker networks. Use overlay networks for inter-container communication.
- **Firewall Rules**: Implement firewall rules to restrict access to container ports and services.

### 7. **Resource Limits**
- **Set Resource Constraints**: Use Docker’s resource limiting features to prevent a single container from consuming excessive CPU or memory.

### 8. **Image Signing and Verification**
- **Sign Images**: Use Docker Content Trust (DCT) to sign images and ensure their integrity and authenticity.
  https://docs.docker.com/engine/security/trust/#:~:text=Docker%20Content%20Trust%20(DCT)%20provides%20the%20ability%20to%20use%20digital
- **Verify Signatures**: Always verify image signatures before deploying images in production.

### 9. **Monitor and Audit**
- **Logging**: Enable logging and monitoring to track container activity and detect anomalies.
- **Regular Audits**: Conduct regular security audits of Docker configurations, images, and running containers.

### 10. **Build Environment Security**
- **Secure Build Systems**: Ensure your CI/CD pipeline and build environments are secure and isolated.
- **Review Dockerfiles**: Regularly review Dockerfiles for security best practices, avoiding common pitfalls like installing unnecessary packages.

### 11. **Patch Management**
- **Regular Scans**: Continuously monitor for vulnerabilities in your images and dependencies.
- **Automate Patching**: Use automated tools to apply patches to images promptly.

### 12. **Remove Unused Images**
- **Clean Up**: Regularly remove unused images and containers to minimize the potential attack surface.

### 13. **Use scanning tool**
- snyk
- whitesource
- trivy  https://aquasecurity.github.io/trivy/v0.19.2/getting-started/installation/


C) PHASE 3: Deploy time security
=========================================================================================
### a) Host hardening:
  - Choice of your operating system
   - Non essential processes - /etc/init.d
   - Host based firewalling (SG, ACL, NACL)
   - Allow /open required ports
   - Default ports -Jenkins/8080 - reconfigure default port / use custom ports Jenkins /8031/8045

### b) Cluster hardening:

### 1. **Control Plane Security**
- **Use Role-Based Access Control (RBAC)**: Implement RBAC to limit user permissions to the minimum required for their roles.
- **Enable API Server Authentication**: Use strong authentication mechanisms like certificates, tokens, or OpenID Connect.
- **Restrict Access to the API Server**: Use network policies or firewalls to limit access to the Kubernetes API server.

### 2. **Network Security**
- **Network Policies**: Define network policies to control traffic between pods and enforce the principle of least privilege.
- **Service Mesh**: Consider using a service mesh (e.g., Istio) for enhanced traffic management and security features, including mTLS.

### 3. **Pod Security**
- **Pod Security Policies (PSP)**: Use PSPs (or the Pod Security Admission in newer versions) to enforce security standards for pods, such as restricting privileged containers.
- **Limit Privileges**: Avoid running containers as root. Use the `USER` directive in your Dockerfiles to specify a non-root user.
- **Resource Requests and Limits**: Define resource requests and limits to prevent denial of service (DoS) attacks.

### 4. **Secrets Management**
- **Use Kubernetes Secrets**: Store sensitive information in Kubernetes Secrets instead of hardcoding them in your application.
- **Encryption at Rest**: Enable encryption for Secrets and other sensitive data stored in etcd.

### 5. **Image Security**
- **Use Trusted Images**: Only use images from trusted sources and scan them for vulnerabilities using tools like Trivy or Clair.
- **Image Signing**: Sign images to verify their integrity and authenticity before deployment.

### 6. **Audit and Logging**
- **Enable Auditing**: Set up audit logging to capture all requests to the API server and monitor for suspicious activity.
- **Centralized Logging**: Use a centralized logging solution (e.g., ELK stack, Fluentd) to aggregate logs from all components for better monitoring and analysis.

### 7. **Regular Updates and Patching**
- **Keep Kubernetes Updated**: Regularly update your Kubernetes cluster and components to apply security patches and fixes.
- **Monitor Vulnerabilities**: Stay informed about vulnerabilities in Kubernetes and its components, and address them promptly.

### 8. **Configuration Management**
- **Use Configuration Files**: Maintain your cluster configurations as code (e.g., using Helm charts or Kustomize) for better management and auditing.
- **Review Configurations**: Regularly review and validate configurations against security best practices.

### 9. **Cluster and Node Security**
- **Isolate Nodes**: Use separate nodes for different workloads (e.g., production, development) to reduce the risk of cross-contamination.
- **Secure Node Access**: Limit SSH access to nodes and use bastion hosts for administration. Implement firewalls and security groups for node-level security.

### 10. **Incident Response**
- **Develop an Incident Response Plan**: Have a plan in place to respond to security incidents, including steps for containment, investigation, and recovery.
- **Regular Drills**: Conduct regular security drills to test your incident response capabilities.

### 11. **Network Time Protocol (NTP)**
- **Time Synchronization**: Ensure that all nodes are time-synchronized using NTP to avoid issues related to timestamps in logs and audit trails.

### 12. **Kubernetes API Rate Limiting**
- **Rate Limiting**: Configure rate limiting for the Kubernetes API server to mitigate the risk of API abuse and denial of service attacks.

By implementing these practices, you can significantly improve the security posture of your Kubernetes cluster and reduce the risk of vulnerabilities and breaches. Regular reviews and updates to your security practices are also essential as threats evolve.

### c) CI/CD Pipeline:

Securing your CI/CD (Continuous Integration/Continuous Deployment) pipeline is critical for protecting your code, data, and deployment processes. Here are some key security principles to follow:

### 1. **Access Control**
- **Least Privilege**: Implement the principle of least privilege for all users and services involved in the CI/CD pipeline. Only grant permissions necessary for specific tasks.
- **Role-Based Access Control (RBAC)**: Define roles with specific permissions to limit access based on job responsibilities.

### 2. **Secure Secrets Management**
- **Environment Variables**: Avoid hardcoding secrets (e.g., API keys, passwords) in your code. Use environment variables or secret management tools.
- **Secret Management Tools**: Utilize tools like HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault for managing secrets securely.

### 3. **Code Review and Approval**
- **Pull Request Reviews**: Require peer reviews for code changes before merging into the main branch. This helps catch vulnerabilities and enforce coding standards.
- **Approval Gates**: Implement approval gates in your pipeline to ensure that critical changes are reviewed and approved by designated team members.

### 4. **Static and Dynamic Code Analysis**
- **Static Analysis Tools**: Integrate tools for static code analysis to identify security vulnerabilities and code quality issues before deployment.
- **Dynamic Testing**: Use dynamic application security testing (DAST) tools during the testing phase to identify runtime vulnerabilities.

### 5. **Dependency Management**
- **Automated Dependency Scans**: Regularly scan dependencies for vulnerabilities using tools like Snyk or Dependabot.
- **Use Trusted Sources**: Only use dependencies from trusted repositories and review their licenses and security status.

### 6. **Pipeline Isolation**
- **Isolation of Build Environments**: Run builds and tests in isolated environments (e.g., containers or virtual machines) to prevent cross-contamination.
- **Separate Environments**: Use separate environments for development, testing, and production to minimize risk.

### 7. **Logging and Monitoring**
- **Audit Logs**: Maintain comprehensive audit logs of all pipeline activities and access to resources.
- **Monitor for Anomalies**: Implement monitoring to detect unusual patterns or unauthorized access attempts in your CI/CD pipeline.

### 8. **Infrastructure as Code (IaC) Security**
- **Secure IaC Templates**: Use security best practices when defining infrastructure as code, ensuring templates are validated for security issues.
- **Automate Security Scans**: Include automated security checks in your CI/CD process to validate IaC configurations.

### 9. **Patch Management**
- **Regular Updates**: Keep CI/CD tools and associated dependencies up to date to protect against known vulnerabilities.
- **Automated Patching**: Implement automated processes to apply security patches as they become available.

### 10. **Network Security**
- **Limit Network Exposure**: Minimize the exposure of build and deployment environments to the public internet. Use VPNs or private networks where possible.
- **Firewall Rules**: Implement firewall rules to restrict access to critical services and resources used in the pipeline.

### 11. **Testing and Quality Assurance**
- **Automated Testing**: Integrate automated testing in your pipeline to validate code changes against security and performance benchmarks.
- **Simulate Attacks**: Conduct regular penetration testing on applications to identify and address vulnerabilities.

### 12. **Incident Response Planning**
- **Plan for Breaches**: Develop an incident response plan that outlines steps to take in the event of a security breach affecting the CI/CD pipeline.
- **Regular Drills**: Conduct regular drills to ensure the team is prepared to respond effectively to security incidents.

By incorporating these principles into your CI/CD pipeline, you can significantly enhance its security and protect your applications from potential vulnerabilities and threats.
  - scan images using registry scanning service.
  - Scan the image after the build 
  - Inline scanning - SonarQube / code quality/vulnerabilities
   -> Secure CI/CD
     - Zero trust policy for CI/CD environment
     - Secure secrets- passwords, access tokens, ssh keys, encryption keys
     - Access control - 2 factor authentication enabled
     - Auditing / monitoring - excessive access, access deprecation
     - organization policies- call out access requirements, separation of responsibilities, secret management, logging
     and monitoring requirements, audit policies

D) PHASE 4: Run time security
===========================================
a) Pod Security Policies (PSPs):
  - Pod security policies
  - PSP capabilities
  - Pod Security context
  - Limitations of PSP
b) Process and Application monitoring:
  - Logging - stream logs to an external location with append-only access from within the cluster. This ensures
  that your logs will not be tampered with even in the case of a total cluster compromise.
  -APM - NewRelic, Prometheus / Grafana / ELK
C) Network security control:
    -> Observability: - the ability to derive actionable insights about the state of K8s from the metrics collected
       - Network Traffic visibility
       - DNS activity logs
       - Application Traffic visibility - response codes, rare or known malicious HTTP HEADERS
       - K8S activity logs - denied logs, SA creation/modification, ns creation/modification
       - machine language and anomaly detection - deviation from derived patterns from data over a period of time.
       - enterprise security controls- leverage the data collected from observability strategy to build reports 
       needed to help with compliance standards e.g HIPPA, PCI
 d) Threat defence:
   - ability to look at malicious activity in the cluster and then defend the cluster from it.
      -> exploit insecure configurations
      -> exploit vulnerability in the application traffic
      -> vulnerability in the code
  - consider both intrusion detection and intrusion prevention
  -> the key to intrusion detection is OBSERVABILITY.
e) Security framework:
   https://attack.mitre.org/matrices/enterprise/cloud/aws/

https://www.microsoft.com/
security/blog/2021/03/23/secure-containerized-environments-with-updated-threatmatrix-for-kubernetes/?_lrsc=2215f5af-27b7-4d0b-abd2-ad3fbd998797
