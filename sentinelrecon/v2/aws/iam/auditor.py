"""IAM Auditor Implementation

AWS IAM audit and analysis.
"""

import logging
from typing import List, Dict, TYPE_CHECKING
from datetime import datetime, timedelta
from botocore.exceptions import ClientError
import json
from .models import IAMUserData, IAMRoleData, AccessKey

if TYPE_CHECKING:
    from sentinelrecon.v2.config import Config
    from sentinelrecon.v2.aws.client import AWSClient

class IAMAuditor:
    """AWS IAM audit and analysis."""
    
    def __init__(self, aws_client: 'AWSClient', config: 'Config', logger: logging.Logger):
        self.aws_client = aws_client
        self.config = config
        self.logger = logger
    
    def audit(self) -> Dict[str, object]:
        """Complete IAM audit.
        
        Returns:
            Dict: Audit results (users, roles, findings)
        """
        self.logger.info("Starting IAM audit...")
        
        try:
            iam_client = self.aws_client.get_iam_client()
            
            users = self._audit_users(iam_client)
            roles = self._audit_roles(iam_client)
            
            self.logger.info(f"IAM audit complete. Found {len(users)} users, {len(roles)} roles")
            
            return {
                'timestamp': datetime.now().isoformat(),
                'users': users,
                'roles': roles,
                'user_count': len(users),
                'role_count': len(roles),
            }
        
        except Exception as e:
            self.logger.error(f"IAM audit failed: {e}")
            raise
    
    def _audit_users(self, iam_client: object) -> List[IAMUserData]:
        """Audit all IAM users.
        
        Returns:
            List[IAMUserData]: User audit results
        """
        users = []
        
        try:
            response = iam_client.list_users()
            
            for user in response.get('Users', []):
                username = user['UserName']
                findings = []
                
                # Get access keys
                keys_response = iam_client.list_access_keys(UserName=username)
                access_keys = []
                
                for key in keys_response.get('AccessKeyMetadata', []):
                    key_age = (datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']).days
                    
                    if key_age > 90:
                        findings.append(f"Access key {key['AccessKeyId'][:10]}... is {key_age} days old")
                    
                    access_keys.append(AccessKey(
                        access_key_id=key['AccessKeyId'],
                        status=key['Status'],
                        created_date=key['CreateDate'],
                        days_old=key_age
                    ))
                
                # Check MFA
                mfa_response = iam_client.list_mfa_devices(UserName=username)
                mfa_enabled = len(mfa_response.get('MFADevices', [])) > 0
                
                if not mfa_enabled and username != 'root':
                    findings.append("MFA not enabled")
                
                # Get policies
                policies = self._get_user_policies(iam_client, username, findings)
                
                # Calculate risk
                risk_level = self._calculate_user_risk(len(access_keys), mfa_enabled, policies, len(findings))
                
                users.append(IAMUserData(
                    username=username,
                    user_id=user['UserId'],
                    arn=user['Arn'],
                    create_date=user['CreateDate'],
                    access_keys=access_keys,
                    mfa_enabled=mfa_enabled,
                    attached_policies=policies,
                    risk_level=risk_level,
                    findings=findings
                ))
        
        except Exception as e:
            self.logger.error(f"Error auditing users: {e}")
        
        return users
    
    def _audit_roles(self, iam_client: object) -> List[IAMRoleData]:
        """Audit all IAM roles.
        
        Returns:
            List[IAMRoleData]: Role audit results
        """
        roles = []
        
        try:
            response = iam_client.list_roles()
            
            for role in response.get('Roles', []):
                role_name = role['RoleName']
                findings = []
                
                # Parse trust relationship
                trust_doc = role.get('AssumeRolePolicyDocument', {})
                trust_services = self._parse_trust_relationship(trust_doc, findings)
                
                # Get policies
                policies = self._get_role_policies(iam_client, role_name, findings)
                
                # Calculate risk
                risk_level = self._calculate_role_risk(policies, len(findings))
                
                roles.append(IAMRoleData(
                    role_name=role_name,
                    role_id=role['RoleId'],
                    arn=role['Arn'],
                    create_date=role['CreateDate'],
                    trust_services=trust_services,
                    attached_policies=policies,
                    risk_level=risk_level,
                    findings=findings
                ))
        
        except Exception as e:
            self.logger.error(f"Error auditing roles: {e}")
        
        return roles
    
    def _get_user_policies(self, iam_client: object, username: str, findings: List[str]) -> List[str]:
        """Get user's attached policies and check for admin access.
        
        Returns:
            List[str]: Policy names
        """
        policies = []
        
        try:
            response = iam_client.list_attached_user_policies(UserName=username)
            
            for policy in response.get('AttachedPolicies', []):
                policy_name = policy['PolicyName']
                policies.append(policy_name)
                
                if 'Admin' in policy_name or 'FullAccess' in policy_name:
                    findings.append(f"User has administrative policy: {policy_name}")
        
        except Exception as e:
            self.logger.warning(f"Error getting policies for {username}: {e}")
        
        return policies
    
    def _get_role_policies(self, iam_client: object, role_name: str, findings: List[str]) -> List[str]:
        """Get role's attached policies.
        
        Returns:
            List[str]: Policy names
        """
        policies = []
        
        try:
            response = iam_client.list_attached_role_policies(RoleName=role_name)
            
            for policy in response.get('AttachedPolicies', []):
                policy_name = policy['PolicyName']
                policies.append(policy_name)
                
                if 'Admin' in policy_name or 'FullAccess' in policy_name:
                    findings.append(f"Role has administrative policy: {policy_name}")
        
        except Exception as e:
            self.logger.warning(f"Error getting policies for {role_name}: {e}")
        
        return policies
    
    def _parse_trust_relationship(self, trust_doc: dict, findings: List[str]) -> List[str]:
        """Parse IAM trust relationship document.
        
        Returns:
            List[str]: Trusted services
        """
        services = []
        
        try:
            statements = trust_doc.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
                
            for statement in statements:
                if statement.get('Effect') == 'Allow':
                    principal = statement.get('Principal', {})
                    
                    if isinstance(principal, dict):
                        if isinstance(principal.get('Service'), list):
                            services.extend(principal['Service'])
                        elif isinstance(principal.get('Service'), str):
                            services.append(principal['Service'])
                        
                        # Check for overly trusting principals
                        if principal.get('AWS') == '*':
                            findings.append("Role trusts any AWS principal (*)")
        
        except Exception as e:
            self.logger.warning(f"Error parsing trust: {e}")
        
        return services
    
    def _calculate_user_risk(self, key_count: int, mfa: bool, policies: List[str], finding_count: int) -> str:
        """Calculate user risk level."""
        if 'Admin' in str(policies) and not mfa:
            return 'CRITICAL'
        
        if 'Admin' in str(policies):
            return 'HIGH'
        
        if not mfa and key_count > 0:
            return 'HIGH'
        
        if finding_count > 2:
            return 'MEDIUM'
        
        return 'LOW'
    
    def _calculate_role_risk(self, policies: List[str], finding_count: int) -> str:
        """Calculate role risk level."""
        if 'Admin' in str(policies):
            return 'HIGH'
        
        if finding_count > 1:
            return 'MEDIUM'
        
        return 'LOW'
