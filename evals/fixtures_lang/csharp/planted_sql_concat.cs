// Planted: the name from the query string is concatenated into the SQL text.
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace Shop.Controllers;

[ApiController]
[Route("api/customers")]
public class CustomersController : ControllerBase
{
    private readonly string _connectionString;

    public CustomersController(IConfiguration config)
    {
        _connectionString = config.GetConnectionString("Shop")!;
    }

    [HttpGet("search")]
    public async Task<IActionResult> Search([FromQuery] string name)
    {
        await using var conn = new SqlConnection(_connectionString);
        await conn.OpenAsync();
        var sql = "SELECT Id, Name, Email FROM Customers WHERE Name LIKE '%" + name + "%'";
        using var cmd = new SqlCommand(sql, conn);
        var results = new List<object>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            results.Add(new { Id = reader.GetInt32(0), Name = reader.GetString(1), Email = reader.GetString(2) });
        }
        return Ok(results);
    }
}
