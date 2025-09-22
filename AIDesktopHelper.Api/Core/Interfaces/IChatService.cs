using System.Threading.Tasks;
using AIDesktopHelper.Api.Models;

namespace AIDesktopHelper.Api.Core.Interfaces
{
    /// <summary>
    /// Domain-driven design service for chat interactions
    /// Represents the core domain service for AI chat functionality
    /// </summary>
    public interface IChatService
    {
        /// <summary>
        /// Gets AI completion for a user prompt
        /// </summary>
        /// <param name="userPrompt">User's input prompt</param>
        /// <param name="userId">User identifier</param>
        /// <returns>AI-generated response</returns>
        Task<string> GetCompletionAsync(string userPrompt, string userId);

        /// <summary>
        /// Gets AI completion with large context support
        /// </summary>
        /// <param name="userPrompt">User's input prompt</param>
        /// <param name="userId">User identifier</param>
        /// <param name="filename">Filename for context</param>
        /// <returns>AI-generated response with context</returns>
        Task<string> GetLargeContextCompletionAsync(string userPrompt, string userId, string filename);

        /// <summary>
        /// Gets streaming completion for real-time responses
        /// </summary>
        /// <param name="userPrompt">User's input prompt</param>
        /// <param name="userId">User identifier</param>
        /// <returns>Async enumerable of response chunks</returns>
        IAsyncEnumerable<string> GetStreamingCompletionAsync(string userPrompt, string userId);

        /// <summary>
        /// Gets conversation history for a user
        /// </summary>
        /// <param name="userId">User identifier</param>
        /// <param name="limit">Maximum number of messages to return</param>
        /// <returns>List of chat messages</returns>
        Task<List<ChatMessage>> GetConversationHistoryAsync(string userId, int limit = 50);

        /// <summary>
        /// Saves a chat message to history
        /// </summary>
        /// <param name="message">Chat message to save</param>
        /// <returns>True if saved successfully</returns>
        Task<bool> SaveMessageAsync(ChatMessage message);

        /// <summary>
        /// Clears conversation history for a user
        /// </summary>
        /// <param name="userId">User identifier</param>
        /// <returns>True if cleared successfully</returns>
        Task<bool> ClearHistoryAsync(string userId);
    }
}
