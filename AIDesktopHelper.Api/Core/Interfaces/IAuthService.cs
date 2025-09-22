using System.Threading.Tasks;

namespace AIDesktopHelper.Api.Core.Interfaces
{
    /// <summary>
    /// Service abstraction for authentication operations
    /// Allows for different implementations (JWT, OAuth, etc.)
    /// </summary>
    public interface IAuthService
    {
        /// <summary>
        /// Authenticates a user with username and password
        /// </summary>
        /// <param name="username">User's username</param>
        /// <param name="password">User's password</param>
        /// <returns>Tuple containing success status and JWT token</returns>
        Task<(bool Success, string Token)> LoginAsync(string username, string password);

        /// <summary>
        /// Registers a new user
        /// </summary>
        /// <param name="username">Desired username</param>
        /// <param name="password">User's password</param>
        /// <returns>True if registration successful</returns>
        Task<bool> RegisterAsync(string username, string password);

        /// <summary>
        /// Validates a JWT token
        /// </summary>
        /// <param name="token">JWT token to validate</param>
        /// <returns>True if token is valid</returns>
        Task<bool> ValidateTokenAsync(string token);

        /// <summary>
        /// Refreshes an expired token
        /// </summary>
        /// <param name="refreshToken">Refresh token</param>
        /// <returns>New JWT token</returns>
        Task<string> RefreshTokenAsync(string refreshToken);

        /// <summary>
        /// Revokes a user's tokens
        /// </summary>
        /// <param name="username">Username to revoke tokens for</param>
        /// <returns>True if revocation successful</returns>
        Task<bool> RevokeTokensAsync(string username);
    }
}
