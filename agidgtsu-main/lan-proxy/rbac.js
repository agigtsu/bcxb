const ROLES = {
    admin: { permissions: ['read', 'write', 'delete', 'admin'], description: 'Full access' },
    user: { permissions: ['read', 'write'], description: 'Read and write' },
    service: { permissions: ['read'], description: 'Read-only' },
    guest: { permissions: [], description: 'No access' }
};

const ENDPOINT_PERMISSIONS = {
    '/v1-internal': ['read', 'write'],
    '/v1/keys/rotate': ['admin'],
    '/v1/keys/status': ['read'],
    '/health': [],
    '/admin/*': ['admin']
};

class RBACManager {
    constructor() {
        this.userRoles = new Map();
    }

    assignRole(userId, role) {
        if (!ROLES[role]) {
            throw new Error(`Invalid role: ${role}`);
        }
        this.userRoles.set(userId, role);
    }

    hasPermission(userId, permission) {
        const role = this.userRoles.get(userId);
        if (!role) return false;
        return ROLES[role].permissions.includes(permission);
    }

    canAccess(userId, endpoint) {
        const requiredPermissions = ENDPOINT_PERMISSIONS[endpoint] || ENDPOINT_PERMISSIONS['/v1-internal'];
        if (requiredPermissions.length === 0) return true;

        const role = this.userRoles.get(userId);
        if (!role) return false;
        return requiredPermissions.some((permission) => ROLES[role].permissions.includes(permission));
    }

    enforcePermission(userId, requiredPermission) {
        if (!this.hasPermission(userId, requiredPermission)) {
            throw new Error(`Permission denied: ${requiredPermission}`);
        }
    }
}

module.exports = { RBACManager, ROLES, ENDPOINT_PERMISSIONS };
