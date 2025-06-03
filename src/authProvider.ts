import {
    AuthenticationDetails,
    CognitoUser,
    CognitoUserPool,
    CognitoUserSession,
    IAuthenticationCallback,
    CognitoUserAttribute,
    ICognitoUserSessionData,
} from 'amazon-cognito-identity-js';
import { type AuthProvider, HttpError, type AuthRedirectResult } from 'react-admin';

// Define or import the missing type
import { ErrorMFASmsRequired } from './errors/ErrorMFASmsRequired';
import { ErrorRequireNewPassword } from './errors/ErrorRequireNewPassword';
import { ErrorMfaTotpRequired } from './errors/ErrorMfaTotpRequired';
import {
    FormData,
    formIsTotpAssociation,
    formIsLogin,
    formIsNewPassword,
    formIsTotp,
} from './localLogin/useCognitoLogin';
import { ErrorMfaTotpAssociationRequired } from './errors/ErrorMfaTotpAssociationRequired';
import { clearLocalStorage, CognitoIdentity, cognitoLogout, createCognitoSession, createCognitoUserPool, NVPair, pkceCognitoLogin } from "./utils/cognitoUtils";
import { CognitoTokens, resolveTokensFromCode, resolveTokensFromUrl } from './utils/cognitoTokens';
import logger from './utils/logger';
import { AuthorisationError } from './errors/AuthorisationError';

/**
 * An authProvider which handles authentication with AWS Cognito.
 *
 * @example
 * ```tsx
 * import React from 'react';
 * import { Admin, Resource } from 'react-admin';
 * import { CognitoAuthProvider } from 'ra-auth-cognito';
 * import { CognitoUserPool } from 'amazon-cognito-identity-js';
 * import dataProvider from './dataProvider';
 * import posts from './posts';
 *
 * const userPool = new CognitoUserPool({
 *     UserPoolId: 'COGNITO_USERPOOL_ID',
 *     ClientId: 'COGNITO_APP_CLIENT_ID',
 * });
 *
 * const authProvider = CognitoAuthProvider(userPool);
 *
 *  const App = () => {
 *   return (
 *        <Admin
 *            authProvider={authProvider}
 *            dataProvider={dataProvider}
 *            title="Example Admin"
 *         >
 *             <Resource name="posts" {...posts} />
 *       </Admin>
 *    );
 * };
 * export default App;
 *
 * ```
 *
 * @param userPool a CognitoUserPool instance
 * @returns an authProvider ready to be used by React-Admin.
 */

export const DEFAULT_ACCESS_TOKEN_EXPIRY_MARGIN = 300; // 5 minutes
export type CognitoAuthProviderOptionsPool = CognitoUserPool;

export type CognitoAuthProviderOptionsIds = {
    userPoolId: string;
    clientId: string;
    hostedUIUrl: string;
    mode: 'oauth' | 'username';
    redirect_uri: string;
    scope: string[];
    oauthGrantType: 'code' | 'implicit';
    accessTokenExpiryMargin?: number;
};

export type CognitoAuthProviderOptions =
    | CognitoAuthProviderOptionsPool
    | CognitoAuthProviderOptionsIds;

export type Config = {
    applicationName?: string;
};

export const CognitoAuthProvider = (
    options: CognitoAuthProviderOptions,
    config: Config = {}
): AuthProvider => {
    let user: CognitoUser | null = null;
    const mode = options instanceof CognitoUserPool ? 'username' : options.mode;

    const userPool =
        options instanceof CognitoUserPool
            ? (options as CognitoUserPool)
            : createCognitoUserPool(options as CognitoAuthProviderOptionsIds);

    const oauthOptions = options as CognitoAuthProviderOptionsIds;
    const { redirect_uri, scope, oauthGrantType, hostedUIUrl, clientId } = oauthOptions as CognitoAuthProviderOptionsIds;
    let doingCheckAuth = false;

    const authProvider: AuthProvider = {
        login: async (form: FormData) => {
            return new Promise((resolve, reject) => {
                if (oauthOptions.mode === 'oauth') {
                    doingCheckAuth = false;
                    return reject(new Error('Login method not supported with OAuth.'));
                }
                const callback: IAuthenticationCallback = {
                    onSuccess: result => {
                        return resolve(result);
                    },
                    onFailure: err => {
                        reject(err);
                    },
                    newPasswordRequired: () => {
                        reject(new ErrorRequireNewPassword());
                    },
                    mfaSetup: () => {
                        user?.associateSoftwareToken({
                            associateSecretCode: secretCode => {
                                reject(
                                    new ErrorMfaTotpAssociationRequired({
                                        secretCode,
                                        username: user!.getUsername(),
                                        applicationName:
                                            config.applicationName ??
                                            window.location.hostname,
                                    })
                                );
                            },
                            onFailure: err => {
                                reject(err);
                            },
                        });
                    },
                    totpRequired: () => {
                        reject(new ErrorMfaTotpRequired());
                    },
                    mfaRequired: () => {
                        reject(
                            new ErrorMFASmsRequired(
                                'SMS MFA is required by the server, but it is not yet supported by ra-auth-cognito. Please disable this feature in Cognito config.'
                            )
                        );
                    },
                };
                if (formIsNewPassword(form)) {
                    const { newPassword, confirmNewPassword, ...attributes } =
                        form;
                    if (!user) {
                        return reject(new Error('User is not defined'));
                    }

                    return user.completeNewPasswordChallenge(
                        newPassword,
                        attributes,
                        callback
                    );
                }
                if (formIsTotp(form)) {
                    if (!user) {
                        return reject(new Error('User is not defined'));
                    }
                    return user.sendMFACode(
                        form.totp,
                        callback,
                        'SOFTWARE_TOKEN_MFA'
                    );
                }

                if (formIsTotpAssociation(form)) {
                    if (!user) {
                        return reject(new Error('User is not defined'));
                    }
                    return user.verifySoftwareToken(
                        form.association,
                        'Authenticator',
                        callback
                    );
                }

                if (!formIsLogin(form)) {
                    return reject(new Error('Invalid form'));
                }
                const { username, password } = form;

                user = new CognitoUser({
                    Username: username,
                    Pool: userPool,
                });

                const authenticationDetails = new AuthenticationDetails({
                    Username: username,
                    Password: password,
                });

                user.authenticateUser(authenticationDetails, callback);
            });
        },
        // called when the user clicks on the logout button
        logout: async () => {
            return new Promise<void>((resolve, reject) => {
                if (mode === 'username') {
                    const user = userPool.getCurrentUser();
                    if (!user) {
                        return resolve();
                    }
                    user.signOut(() => {
                        resolve();
                    })
                } else {
                    cognitoLogout(oauthOptions)
                        .then((logoutUrl) => {
                            user = null;
                            if (logoutUrl) {
                                window.location.assign(logoutUrl);
                            }
                        })
                        .catch((err) => {
                            // If Cognito logout fails, still clear local state
                            logger.error('Cognito Logout Callback (error):', err);
                            clearLocalStorage();
                        });
                }
            });
        },
        // called when the API returns an error
        checkError: async ({ status }: { status: number }) => {
            if (status === 401 || status === 403) {
                const error = new AuthorisationError(`Unauthorized (${status})`);
                error.redirectTo = mode === 'oauth' ? '/' : '/login';
                error.logoutUser = true;
                throw error;
            }
        },
        // called when the user navigates to a new location, to check for authentication
        checkAuth: async () => {
            return new Promise<void>(async (resolve, reject) => {
                if (doingCheckAuth) {
                    return resolve();
                }
                doingCheckAuth = mode === 'oauth';
                const url = new URL(window.location.href);
                const redirectToOAuthIfNeeded = async (error?: Error) => {
                    logger.error('CheckAuth error:', error?.message, url);
                    if (mode === 'oauth') {
                        if (oauthGrantType === 'code') {
                            if (!user) {
                                const loginUrl = await pkceCognitoLogin(window.location.href, oauthOptions);
                                window.location.assign(loginUrl!);
                            } else {
                                const session = await new Promise<CognitoUserSession>((resolve, reject) => {
                                    user!.getSession((err: Error | null, session: CognitoUserSession) => {
                                        if (err) {
                                            user = null;
                                            reject(err);
                                        } else {
                                            resolve(session);
                                        }
                                    });
                                });

                                if (!session || !session.isValid()) {
                                    const loginUrl = await pkceCognitoLogin(window.location.href, oauthOptions);
                                    window.location.assign(loginUrl!);
                                }
                            }
                            doingCheckAuth = false;
                            return resolve();
                        } else { //implicit flow
                            const url = `${hostedUIUrl}/login` +
                                `?client_id=${clientId}&response_type=token` +
                                `&scope=${scope!.join('+')}&redirect_uri=${redirect_uri}`;
                            window.location.assign(url);
                        }
                    } else {
                        return reject(error);
                    }
                };
                let user = userPool.getCurrentUser();

                if (!user) {
                    return redirectToOAuthIfNeeded(
                        new HttpError('No user!', 401)
                    );
                }
                user.getSession((err: any, session: CognitoUserSession) => {
                    if (err) {
                        return redirectToOAuthIfNeeded(
                            new HttpError('No user session', 401)
                        );
                    }

                    if (!session.isValid()) {
                        return redirectToOAuthIfNeeded(
                            new HttpError('No valid user session', 401)
                        );
                    }

                    user!.getUserAttributes(err => {
                        if (err) {
                            return reject(err);
                        }
                        doingCheckAuth = false;
                        resolve();
                    });
                });
            });
        },
        // called when the user navigates to a new location, to check for permissions / roles
        getPermissions: async () => {
            return new Promise((resolve, reject) => {
                if (doingCheckAuth) {
                    return reject('Checking auth, please try again later');
                }
                const user = userPool.getCurrentUser();

                if (!user) {
                    return resolve([]);
                }

                user.getSession((err: Error | null, session: CognitoUserSession) => {
                    if (err) {
                        return reject(err);
                    }
                    if (!session || !session.isValid()) {
                        return reject();
                    }
                    const token = session.getIdToken().decodePayload();
                    return resolve(token['cognito:groups'] ?? []);
                });
            });
        },
        getIdentity: async () => {
            return new Promise<CognitoIdentity>((resolve, reject) => {
                if (doingCheckAuth) {
                    return reject();
                }
                const user = userPool.getCurrentUser();

                if (!user) {
                    return reject();
                }
                user.getSession((err: Error | null, session: CognitoUserSession) => {
                    if (err) {
                        return reject(err);
                    }
                    if (!session.isValid()) {
                        return reject();
                    }
                    user!.getUserAttributes((err: Error | undefined, attributes?: CognitoUserAttribute[]) => {
                        if (err) {
                            return reject(err);
                        }

                        resolve({
                            id: user!.getUsername(),
                            fullName: attributes!.find((attribute: NVPair) => attribute.Name === 'name')?.Value,
                            avatar: attributes!.find((attribute: NVPair) => attribute.Name === 'picture')?.Value,
                            cognitoUser: user,
                        } as CognitoIdentity);
                    });
                });
            });
        },
        handleCallback: async () => {
            return new Promise<AuthRedirectResult | void | any>(async (resolve, reject) => {
                if (oauthOptions.mode === 'username') {
                    return reject(new Error('Username mode not supported for handleCallback'));
                }
                doingCheckAuth = false;
                let tokens: CognitoTokens;
                const url = new URL(window.location.href);
                if (oauthOptions.oauthGrantType === 'code') {
                    const code = url.searchParams.get('code');
                    if (!code) {
                        reject(new HttpError('No authorization code in callback URL', 400));
                    }
                    tokens = await resolveTokensFromCode(code!, oauthOptions);

                    // Clean up code verifier
                    sessionStorage.removeItem('pkce_code_verifier');
                } else {
                    try {
                        const hash = url.hash || window.location.hash;
                        if (!hash?.startsWith('#')) {
                            return reject(new HttpError('Invalid OAuth implicit callback URL', 400));
                        }
                        const hashParams = new URLSearchParams(hash.substring(1));

                        if (hashParams.has('error')) {
                            const error = new HttpError(`${hashParams.get('error')} - ${hashParams.get('error_description') || 'OAuth implicit callback error}'}`, 400);
                            logger.error('Error in OAuth implicit callback:', error);
                            return reject(error);
                        }
                        tokens = resolveTokensFromUrl(hashParams);
                    } catch (error) {
                        logger.error('Error resolving implicit tokens from URL hash:', error);
                        return reject(error);
                    }
                }
                // Store tokens
                localStorage.setItem('auth', JSON.stringify(tokens));

                user = createCognitoSession(tokens, userPool);

                // Redirect back to where user was
                try {
                    let previousUrl = localStorage.getItem('currentUrl');
                    localStorage.removeItem('currentUrl');
                    try {
                        // only redirect to previous URL if provided, is valid and is same hostname 
                        // this is to prevent open redirect vulnerabilities (CWE-601)
                        const url = new URL(previousUrl!);
                        if (url.hostname && url.hostname !== window.location.hostname) {
                            throw new Error('Unexpected hostname in previous URL - ignoring and redirecting to home');
                        }
                    } catch (error) {
                        logger.error('Error getting/parsing previous URL:', error);
                        previousUrl = '/';
                    }
                    window.location.assign(previousUrl || '/');
                } catch (error) {
                    logger.error('Error getting previous URL:', error);
                    reject(error);
                }
                resolve({})
            });
        },
    };

    return authProvider;
};

