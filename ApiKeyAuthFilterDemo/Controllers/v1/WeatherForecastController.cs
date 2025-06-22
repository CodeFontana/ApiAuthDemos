using ApiKeyAuthFilterDemo.Filters;
using ApiKeyAuthFilterDemo.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace ApiKeyAuthFilterDemo.Controllers.v1;

[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
[EnableRateLimiting("fixed")]
public class WeatherForecastController : ControllerBase
{
    private static readonly string[] Summaries =
    [
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    ];

    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ServiceFilter(typeof(ApiKeyAuthFilter))]
    // [ApiKeyAuthFilter] <-- Alternate approach, see ApiKeyAuthFilter.cs
    public IEnumerable<WeatherForecastModel> Get()
    {
        return Enumerable.Range(1, 5).Select(index => new WeatherForecastModel
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray();
    }
}
