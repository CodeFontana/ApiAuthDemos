using JwtAndApiKeyAuthDemo;
using JwtAndApiKeyAuthDemo.Services;
using JwtAndAPiKeyAuthDemo.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using System.Text.Json.Serialization;

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
    options.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme()
    {
        Name = "X-API-KEY",
        Type = SecuritySchemeType.ApiKey,
        In = ParameterLocation.Header,
        Description = "API key authorization header.",
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "ApiKey"
                }
            },
            new string[] {}
        }
    });
});
builder.Services.AddApiVersioning(options =>
{
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.DefaultApiVersion = new(1, 0);
    options.ReportApiVersions = true;
});
builder.Services.AddVersionedApiExplorer(options =>
{
    options.GroupNameFormat = "'v'VVV";
    options.SubstituteApiVersionInUrl = true;
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = "JwtOrApiKey";
    options.DefaultChallengeScheme = "JwtOrApiKey";
})
.AddPolicyScheme("JwtOrApiKey", "Authorization JWT Bearer or API key", options =>
{
    options.ForwardDefaultSelector = context =>
    {
        string authHeader = context.Request.Headers["Authorization"].FirstOrDefault();

        if (authHeader?.StartsWith("Bearer ") == true)
        {
            return JwtBearerDefaults.AuthenticationScheme;
        }

        return ApiKeyAuthenticationDefaults.AuthenticationScheme;
    };
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
                builder.Configuration.GetValue<string>("Authentication:JwtSecurityKey"))),
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromMinutes(10)
    };
})
.AddApiKey<ApiKeyAuthenticationService>();

builder.Services.AddCors(policy =>
{
    policy.AddPolicy("OpenCorsPolicy", options =>
        options
            .AllowAnyOrigin()
            .AllowAnyHeader()
            .AllowAnyMethod());
});
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IApiKeyAuthenticationService, ApiKeyAuthenticationService>();
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
app.UseAuthentication();
app.UseAuthorization();
app.UseAuthorization();
app.MapControllers();
app.MapHealthChecks("/api/health");
app.Run();
