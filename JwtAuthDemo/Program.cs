using System.Net.Mime;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using JwtAuthDemo.Interfaces;
using JwtAuthDemo.Services;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers().AddJsonOptions(config =>
{
    config.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
});
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "WebApi v1",
        Version = "v1",
        Description = "This is a demo API"
    });
    //options.SwaggerDoc("v2", new OpenApiInfo
    //{
    //    Title = "WebApi v2",
    //    Version = "v2",
    //    Description = "This is a demo API"
    //});
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Specify JWT bearer token",
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    Array.Empty<string>()
                }
            });
});
builder.Services.AddApiVersioning(options =>
{
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.DefaultApiVersion = new(1, 0);
    options.ReportApiVersions = true;
})
    .AddMvc()
    .AddApiExplorer(options =>
    {
        options.GroupNameFormat = "'v'VVV";
        options.SubstituteApiVersionInUrl = true;
    });
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = "Bearer";
    options.DefaultChallengeScheme = "Bearer";
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new()
    {
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration.GetValue<string>("Authentication:JwtIssuer"),
        ValidateAudience = true,
        ValidAudience = builder.Configuration.GetValue<string>("Authentication:JwtAudience"),
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(
    Encoding.ASCII.GetBytes(
        builder.Configuration.GetValue<string>("Authentication:JwtSecurityKey")
            ?? throw new InvalidOperationException("JWTSecurityKey is not configured"))),
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromMinutes(10)
    };
});
builder.Services.AddCors(policy =>
{
    policy.AddPolicy("OpenCorsPolicy", options =>
        options
            .AllowAnyOrigin()
            .AllowAnyHeader()
            .AllowAnyMethod());
});
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("fixed", limiterOptions =>
    {
        limiterOptions.PermitLimit = 4;
        limiterOptions.Window = TimeSpan.FromSeconds(12);
        limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        limiterOptions.QueueLimit = 0;
    });

    options.OnRejected = (context, cancellationToken) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.HttpContext.Response.ContentType = MediaTypeNames.Text.Plain;
        context.HttpContext.RequestServices.GetService<ILoggerFactory>()?
            .CreateLogger("Microsoft.AspNetCore.RateLimitingMiddleware")
            .LogWarning("OnRejected: {GetUserEndPoint}", GetUserEndPoint(context.HttpContext));
        context.HttpContext.Response.WriteAsync("Rate limit exceeded. Please try again later.", cancellationToken: cancellationToken);
        return new ValueTask();
    };
});
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddHealthChecks();
WebApplication app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        // options.SwaggerEndpoint("/swagger/v2/swagger.json", "WebApi v2");
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "WebApi v1");
        options.EnableTryItOutByDefault();
        options.ConfigObject.AdditionalItems["syntaxHighlight"] = new Dictionary<string, object>
        {
            ["activated"] = false
        };
    });
}

app.UseHttpsRedirection();
app.UseCors("OpenCorsPolicy");
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapHealthChecks("/api/health").AllowAnonymous();
app.Run();

static string GetUserEndPoint(HttpContext context) =>
    $"User {context.User.Identity?.Name ?? "Anonymous"}, " +
    $"Endpoint: {context.Request.Path}, " +
    $"IP: {context.Connection.RemoteIpAddress}";