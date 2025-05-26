/**
 * Error thrown when a user is required to set their password after signing-in with a temporary password.
 */
export class AuthorisationError extends Error {
    redirectTo!: string;
    logoutUser!: boolean;
    constructor(message?: string) {
        super(message);
        Object.setPrototypeOf(this, AuthorisationError.prototype);
    }

}
