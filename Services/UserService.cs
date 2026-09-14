public static class UserService
{
    public static bool IsUsernameTaken(string username)
    {
        var query = "SELECT COUNT(*) FROM Users WHERE Username = @username";
        var args = new Dictionary<string, string> { { "@username", username } };
        int count;
        try
        {
            count = DataBaseService.ReadOne<int>(query, args);
            
        } catch (InvalidOperationException)
        {
            return false;
        }
        return count > 0;
    }

    
}