"""Example of using the repository library to build a repository"""

import copy
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Union, Any, Optional

from securesystemslib.signer import CryptoSigner, Key, Signer

from tuf.api.exceptions import RepositoryError
from tuf.api.metadata import (
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Root,
    RootVerificationResult,
    Signed,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
    VerificationResult,
)
from tuf.repository import Repository

logger = logging.getLogger(__name__)

_signed_init = {
    Root.type: Root,
    Snapshot.type: Snapshot,
    Targets.type: Targets,
    Timestamp.type: Timestamp,
}


class SimpleRepository(Repository):
    """In-memory repository implementation with configurable parameters

    Attributes:
        role_cache: Historical metadata versions for all roles
        signer_cache: All signers available to the repository
        target_cache: All target files served by the repository
        _metrics: Internal metrics tracking for repository operations
    """

    def __init__(
        self, 
        expiry_period: timedelta = timedelta(days=1),
        default_targets_path: str = "*",
        custom_logger: Optional[logging.Logger] = None
    ) -> None:
        """
        Initialize the repository with configurable parameters
        
        Args:
            expiry_period (timedelta): Period after which metadata expires
            default_targets_path (str): Default path pattern for targets
            custom_logger (logging.Logger, optional): Custom logger instance
        """
        # Configurable expiry period
        self.expiry_period = expiry_period
        self.default_targets_path = default_targets_path
        
        # Use provided logger or create a default one
        self.logger = custom_logger or logger
        
        # all versions of all metadata
        self.role_cache: dict[str, list[Metadata]] = defaultdict(list)
        # all current keys
        self.signer_cache: dict[str, list[Signer]] = defaultdict(list)
        # all target content
        self.target_cache: dict[str, bytes] = {}
        
        # Metrics tracking
        self._metrics = {
            'total_targets': 0,
            'total_delegations': 0,
            'metadata_versions': defaultdict(int)
        }
        
        # version cache for snapshot and all targets, updated in close().
        self._snapshot_info = MetaFile(1)
        self._targets_infos: dict[str, MetaFile] = defaultdict(
            lambda: MetaFile(1)
        )

        # setup a basic repository, generate signing key per top-level role
        with self.edit_root() as root:
            for role in ["root", "timestamp", "snapshot", "targets"]:
                signer = CryptoSigner.generate_ecdsa()
                self.signer_cache[role].append(signer)
                root.add_key(signer.public_key, role)

        for role in ["timestamp", "snapshot", "targets"]:
            with self.edit(role):
                pass

    def _update_metrics(self, metric_type: str, value: Any = 1):
        """Update internal metrics"""
        if metric_type in self._metrics:
            self._metrics[metric_type] += value

    def get_repository_metrics(self) -> dict:
        """
        Retrieve repository performance and usage metrics
        
        Returns:
            dict: Repository metrics
        """
        return {
            'total_targets': self._metrics['total_targets'],
            'total_delegations': self._metrics['total_delegations'],
            'metadata_versions': dict(self._metrics['metadata_versions']),
            'current_cache_sizes': {
                'roles': len(self.role_cache),
                'targets': len(self.target_cache),
                'signers': len(self.signer_cache)
            }
        }

    def validate_target_path(self, path: str) -> bool:
        """
        Validate and sanitize target path to prevent potential security issues
        
        Args:
            path (str): Target path to validate
        
        Returns:
            bool: Whether the path is valid
        """
        # Prevent directory traversal
        if '..' in path or path.startswith('/'):
            self.logger.warning(f"Potential directory traversal attempt: {path}")
            return False
        
        # Optional: Add more sophisticated path validation
        if len(path) > 255:
            self.logger.warning(f"Target path too long: {path}")
            return False
        
        return True

    @property
    def targets_infos(self) -> dict[str, MetaFile]:
        return self._targets_infos

    @property
    def snapshot_info(self) -> MetaFile:
        return self._snapshot_info

    def _get_verification_result(
        self, role: str, md: Metadata
    ) -> Union[VerificationResult, RootVerificationResult]:
        """Verify roles metadata using the existing repository metadata"""
        if role == Root.type:
            assert isinstance(md.signed, Root)
            root = self.root()
            previous = root if root.version > 0 else None
            return md.signed.get_root_verification_result(
                previous, md.signed_bytes, md.signatures
            )
        if role in [Timestamp.type, Snapshot.type, Targets.type]:
            delegator: Signed = self.root()
        else:
            delegator = self.targets()
        return delegator.get_verification_result(
            role, md.signed_bytes, md.signatures
        )

    def open(self, role: str) -> Metadata:
        """Return current Metadata for role from 'storage'
        (or create a new one)
        """
        if role not in self.role_cache:
            signed_init = _signed_init.get(role, Targets)
            md = Metadata(signed_init())

            # this makes version bumping in close() simpler
            md.signed.version = 0
            return md

        # return latest metadata from storage (but don't return a reference)
        return copy.deepcopy(self.role_cache[role][-1])

    def close(self, role: str, md: Metadata) -> None:
        """Store a version of metadata. Handle version bumps, expiry, signing"""
        md.signed.version += 1
        md.signed.expires = datetime.now(timezone.utc) + self.expiry_period

        md.signatures.clear()
        for signer in self.signer_cache[role]:
            md.sign(signer, append=True)

        # Double check that we only write verified metadata
        vr = self._get_verification_result(role, md)
        if not vr:
            raise ValueError(f"Role {role} failed to verify")
        keyids = [keyid[:7] for keyid in vr.signed]
        verify_str = f"verified with keys [{', '.join(keyids)}]"
        self.logger.debug("Role %s v%d: %s", role, md.signed.version, verify_str)

        # Update metrics
        self._metrics['metadata_versions'][role] += 1

        # store new metadata version, update version caches
        self.role_cache[role].append(md)
        if role == "snapshot":
            self._snapshot_info.version = md.signed.version
        elif role not in ["root", "timestamp"]:
            self._targets_infos[f"{role}.json"].version = md.signed.version

    def add_target(self, path: str, content: str) -> bool:
        """Enhanced add_target with additional validations"""
        if not self.validate_target_path(path):
            self.logger.error(f"Invalid target path: {path}")
            return False
        
        try:
            data = bytes(content, "utf-8")
            
            # Additional optional content validation
            if len(data) > 10 * 1024 * 1024:  # 10 MB limit
                self.logger.warning(f"Target content exceeds size limit: {path}")
                return False
            
            # Add content to cache for serving to clients
            self.target_cache[path] = data

            # Add a target in the targets metadata
            with self.edit_targets() as targets:
                targets.targets[path] = TargetFile.from_data(path, data)

            # Update metrics
            self._update_metrics('total_targets')

            # Update snapshot, timestamp
            self.do_snapshot()
            self.do_timestamp()
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to add target {path}: {e}")
            return False

    def submit_delegation(self, rolename: str, data: bytes) -> bool:
        """Add a delegation to a (offline signed) delegated targets metadata"""
        try:
            # More robust error handling and logging
            if not data:
                self.logger.error(f"Empty delegation data for role {rolename}")
                return False

            try:
                delegation_data = json.loads(data)
                if not delegation_data:
                    self.logger.warning(f"No key information in delegation for role {rolename}")
                    return False
            except json.JSONDecodeError as json_error:
                self.logger.error(f"Invalid JSON in delegation for {rolename}: {json_error}")
                return False

            # Existing logic with improved error handling
            try:
                keyid, keydict = next(iter(delegation_data.items()))
                key = Key.from_dict(keyid, keydict)

                # Add delegation and key
                role = DelegatedRole(rolename, [], 1, True, [f"{rolename}/*"])
                with self.edit_targets() as targets:
                    if targets.delegations is None:
                        targets.delegations = Delegations({}, {})
                    if targets.delegations.roles is None:
                        targets.delegations.roles = {}
                    
                    # Check for existing role before adding
                    if rolename in targets.delegations.roles:
                        self.logger.warning(f"Delegation for role {rolename} already exists. Overwriting.")
                    
                    targets.delegations.roles[rolename] = role
                    targets.add_key(key, rolename)

            except (RepositoryError, KeyError) as e:
                self.logger.error(f"Failed to process delegation for {rolename}: {e}")
                return False

        except Exception as unexpected_error:
            self.logger.critical(f"Unexpected error in submit_delegation: {unexpected_error}")
            return False

        # Update metrics
        self._update_metrics('total_delegations')

        # Update snapshot and timestamp
        try:
            self.do_snapshot()
            self.do_timestamp()
        except Exception as update_error:
            self.logger.error(f"Failed to update snapshot/timestamp after delegation: {update_error}")
            return False

        return True

    def submit_role(self, role: str, data: bytes) -> bool:
        """Add a new version of a delegated roles metadata"""
        try:
            self.logger.debug("Processing new version for role %s", role)
            if role in ["root", "snapshot", "timestamp", "targets"]:
                raise ValueError("Only delegated targets are accepted")

            md = Metadata.from_bytes(data)
            for targetpath in md.signed.targets:
                if not targetpath.startswith(f"{role}/"):
                    raise ValueError(f"targets allowed under {role}/ only")

            if md.signed.version != self.targets(role).version + 1:
                raise ValueError(f"Invalid version {md.signed.version}")

        except (RepositoryError, ValueError) as e:
            self.logger.info("Failed to add new version for %s: %s", role, e)
            return False

        # Check that we only write verified metadata
        vr = self._get_verification_result(role, md)
        if not vr:
            self.logger.info("Role %s failed to verify", role)
            return False

        keyids = [keyid[:7] for keyid in vr.signed]
        verify_str = f"verified with keys [{', '.join(keyids)}]"
        self.logger.debug("Role %s v%d: %s", role, md.signed.version, verify_str)

        # Checks passed: Add new delegated role version
        self.role_cache[role].append(md)
        self._targets_infos[f"{role}.json"].version = md.signed.version

        # To keep it simple, target content is generated from targetpath
        for targetpath in md.signed.targets:
            self.target_cache[targetpath] = bytes(f"{targetpath}", "utf-8")

        # Update metrics
        self._metrics['metadata_versions'][role] += 1

        # Update snapshot, timestamp
        self.do_snapshot()
        self.do_timestamp()

        return True
