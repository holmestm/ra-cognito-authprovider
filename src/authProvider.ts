import {
    AuthenticationDetails,
    CognitoAccessToken,
    CognitoIdToken,
    CognitoRefreshToken,
    CognitoUser,
    CognitoUserPool,
    CognitoUserSession,
    IAuthenticationCallback,
} from 'amazon-cognito-identity-js';
import { type AuthProvider, HttpError, type AuthRedirectResult, addRefreshAuthToAuthProvider } from 'react-admin';
import { QueryFunctionContext } from '@tanstack/react-query'; // Ensure this package is installed

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
} from './useCognitoLogin';
import { ErrorMfaTotpAssociationRequired } from './errors/ErrorMfaTotpAssociationRequired';
import { clearLocalStorage, CognitoIdentity, cognitoLogout, createCognitoSession, NVPair, pkceCognitoLogin } from "./utils/cognitoUtils";
import { resolveTokens, CognitoTokens, aboutToExpire, refreshTokens } from './utils/cognitoTokens';
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
    hostedUIUrl?: string;
    mode: 'oauth' | 'username';
    redirect_uri?: string;
    scope?: string[];
    oauthGrantType?: 'code' | 'implicit';
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
            : new CognitoUserPool({
                UserPoolId: options.userPoolId,
                ClientId: options.clientId,
            });

    const oauthOptions = options as CognitoAuthProviderOptionsIds;
    const { redirect_uri, scope, oauthGrantType, hostedUIUrl, clientId, accessTokenExpiryMargin } = { accessTokenExpiryMargin: DEFAULT_ACCESS_TOKEN_EXPIRY_MARGIN, ...oauthOptions };
    let doingCheckAuth = false;

    const authProvider = {
        login: async (form: FormData) => {
            logger.info(`Login called [${doingCheckAuth}]:`, form);
            if (oauthOptions.mode === 'oauth') {
                doingCheckAuth = false;
                window.location.assign(`${window.location.origin}/`);
                return true;
            }
            return new Promise((resolve, reject) => {
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
                        user.associateSoftwareToken({
                            associateSecretCode: secretCode => {
                                reject(
                                    new ErrorMfaTotpAssociationRequired({
                                        secretCode,
                                        username: user.getUsername(),
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
            logger.info(`Logout called [${doingCheckAuth}]:`);
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
                                logger.info('Cognito Logout Callback, redirecting to', logoutUrl);
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
            logger.info(`checkError [${doingCheckAuth}]:`, status);
            if (status === 401 || status === 403) {
                const error = new AuthorisationError(`Unauthorized (${status})`);
                error.redirectTo = mode === 'oauth' ? '/' : '/login';
                error.logoutUser = true;
                throw error;
            }
        },
        // called when the user navigates to a new location, to check for authentication
        checkAuth: async () => {
            logger.info(`checkAuth called [${doingCheckAuth}]:`);
            return new Promise<void>(async (resolve, reject) => {
                if (doingCheckAuth) {
                    return resolve();
                }
                doingCheckAuth = mode === 'oauth';
                const url = new URL(window.location.href);
                const redirectToOAuthIfNeeded = async (error?: Error) => {
                    logger.error('CheckAuth error:', error.message, url);
                    if (mode === 'oauth') {
                        if (oauthGrantType === 'code') {
                            if (!user) {
                                const loginUrl = await pkceCognitoLogin(window.location.href, oauthOptions);
                                window.location.assign(loginUrl);
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
                                    await pkceCognitoLogin(url.toString(), oauthOptions);
                                }
                            }
                            doingCheckAuth = false;
                            return resolve();
                        } else { //implicit flow
                            const url = `${hostedUIUrl}/login` +
                                `?client_id=${clientId}&response_type=token` +
                                `&scope=${scope.join('+')}&redirect_uri=${redirect_uri}`;
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

                    user.getUserAttributes(err => {
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
                logger.info(`getPermissions called [${doingCheckAuth}]:`);
                if (doingCheckAuth) {
                    return reject('Checking auth, please try again later');
                }
                const user = userPool.getCurrentUser();

                if (!user) {
                    return resolve([]);
                }

                user.getSession((err: Error, session: CognitoUserSession) => {
                    if (err) {
                        return reject(err);
                    }
                    if (!session.isValid()) {
                        return reject();
                    }
                    const token = session.getIdToken().decodePayload();
                    return resolve(token['cognito:groups'] ?? []);
                });
            });
        },
        getIdentity: async () => {
            return new Promise<CognitoIdentity>((resolve, reject) => {
                logger.info(`getIdentity called [${doingCheckAuth}]:`);
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
                    user.getUserAttributes((err: Error | null, attributes?: NVPair[]) => {
                        if (err) {
                            return reject(err);
                        }

                        resolve({
                            id: user.getUsername(),
                            fullName: attributes?.find((attribute: NVPair) => attribute.Name === 'name')?.Value,
                            avatar: attributes?.find((attribute: NVPair) => attribute.Name === 'picture')?.Value,
                            cognitoUser: user,
                        } as CognitoIdentity);
                    });
                });
            });
        },
        handleCallback: async (params?: QueryFunctionContext) => {
            return new Promise<AuthRedirectResult | void | any>(async (resolve, reject) => {
                logger.info(`handleCallback called [${doingCheckAuth}]:`);
                doingCheckAuth = false;
                if (oauthOptions.oauthGrantType === 'code') {
                    const url = new URL(window.location.href);
                    const code = url.searchParams.get('code');
                    if (!code) {
                        throw new Error('No authorization code in callback URL');
                    }
                    const tokens: CognitoTokens = await resolveTokens(code, oauthOptions);

                    // Store tokens
                    localStorage.setItem('auth', JSON.stringify(tokens));

                    // Clean up code verifier
                    sessionStorage.removeItem('pkce_code_verifier');

                    user = createCognitoSession(tokens, userPool);

                    logger.info('User Object Created:', user);

                    // Redirect back to where user was
                    try {
                        const previousUrl = localStorage.getItem('currentUrl');
                        localStorage.removeItem('currentUrl');
                        window.location.assign(previousUrl);
                        resolve({})
                    } catch (error) {
                        logger.error('Error getting previous URL:', error);
                        reject(error);
                    }
                } else { //implicit flow, tokens should be in hash fragment
                    const urlParams = new URLSearchParams(
                        window.location.hash.substring(1)
                    );
                    const error = urlParams.get('error');
                    const errorDescription = urlParams.get('error_description');
                    const idToken = urlParams.get('id_token');
                    const accessToken = urlParams.get('access_token');

                    if (error) {
                        reject(error);
                    }

                    if (idToken == null || accessToken == null) {
                        throw new Error('Failed to handle login callback (implicit oauth flow).');
                    }
                    const session = new CognitoUserSession({
                        IdToken: new CognitoIdToken({ IdToken: idToken }),
                        RefreshToken: new CognitoRefreshToken({
                            RefreshToken: null,
                        }),
                        AccessToken: new CognitoAccessToken({
                            AccessToken: accessToken,
                        }),
                    });
                    const user = new CognitoUser({
                        Username: session.getIdToken().decodePayload()[
                            'cognito:username'
                        ],
                        Pool: userPool,
                        Storage: window.localStorage,
                    });
                    user.setSignInUserSession(session);
                    resolve({})
                }
            })
        },
    };
    return addRefreshAuthToAuthProvider(authProvider, async () => {
        if (aboutToExpire(accessTokenExpiryMargin!)) {
            await refreshTokens(oauthOptions);
        }
    });
};
