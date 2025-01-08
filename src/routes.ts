/**
 * An array of routes that accessible to the public
 * these routes do not require authentication
 * @type {string[]}
 */
export const publicRoutes = ["/"];

/**
 * An array of routes that are used for authentication
 * these routes wil redirect login users to dashbord or settings
 * @type {string[]}
 */
export const authRoutes = [
  "/auth/new-verification",
  "/auth/login",
  "/auth/register",
  "/auth/error",
  "/auth/reset",
  "/auth/new-password",
];

/**
 * the prefix for API authentication prefix
 * Routes that start with this prefix are used for API authentication purposes
 * @type {string}
 */
export const apiAuthPrefix = "/api/auth";

/**
 * the default redirect path after loggin
 * @type {string}
 */
export const DEFAULT_LOGIN_REDIRECT = "/dashboard";
